from django.utils.timezone import now as tz_now

from awx.main.models import (
    Job,
    ProjectUpdate,
    InventoryUpdate,
    SystemJob,
    AdHocCommand,
    WorkflowJob,
)

def _model_name_id(model, id):
    return f"{model._meta.model_name}-{id}"

class DependencyGraph(object):
    PROJECT_UPDATES = 'project_updates'
    INVENTORY_UPDATES = 'inventory_updates'

    JOB_TEMPLATE_JOBS = 'job_template_jobs'

    SYSTEM_JOB = 'system_job'
    INVENTORY_SOURCE_UPDATES = 'inventory_source_updates'
    WORKFLOW_JOB_TEMPLATES_JOBS = 'workflow_job_template_jobs'

    INVENTORY_SOURCES = 'inventory_source_ids'

    def __init__(self):
        self.data = {}
        # project_id -> True / False
        self.data[self.PROJECT_UPDATES] = {}
        # inventory_id -> True / False
        self.data[self.INVENTORY_UPDATES] = {}
        # job_template_id -> True / False
        self.data[self.JOB_TEMPLATE_JOBS] = {}

        '''
        Track runnable job related project and inventory to ensure updates
        don't run while a job needing those resources is running.
        '''

        # inventory_source_id -> True / False
        self.data[self.INVENTORY_SOURCE_UPDATES] = {}
        # True / False
        self.data[self.SYSTEM_JOB] = (True, None)
        # workflow_job_template_id -> True / False
        self.data[self.WORKFLOW_JOB_TEMPLATES_JOBS] = {}

        # inventory_id -> [inventory_source_ids]
        self.data[self.INVENTORY_SOURCES] = {}

    def _get_data_item(self, key, id):
        return self.data[key].get(id, (True, None))

    def get_now(self):
        return tz_now()

    def mark_system_job(self, job):
        self.data[self.SYSTEM_JOB] = (False, _model_name_id(SystemJob, job.id))

    def mark_project_update(self, job):
        self.data[self.PROJECT_UPDATES][job.project_id] = (False, _model_name_id(ProjectUpdate, job.id))

    def mark_inventory_update(self, job):
        self.data[self.INVENTORY_UPDATES][job.inventory_source.inventory_id] = (False, _model_name_id(InventoryUpdate, job.id))

    def mark_inventory_source_update(self, job):
        self.data[self.INVENTORY_SOURCE_UPDATES][job.inventory_source_id] = (False, _model_name_id(InventoryUpdate, job.id))

    def mark_job_template_job(self, job):
        self.data[self.JOB_TEMPLATE_JOBS][job.job_template_id] = (False, _model_name_id(Job, job.id))

    def mark_workflow_job(self, job):
        self.data[self.WORKFLOW_JOB_TEMPLATES_JOBS][job.workflow_job_template_id] = (False, _model_name_id(WorkflowJob, job.id))

    def can_project_update_run(self, job):
        return self._get_data_item(self.PROJECT_UPDATES, job.project_id)

    def can_inventory_update_run(self, job):
        return self._get_data_item(self.INVENTORY_SOURCE_UPDATES, job.inventory_source_id)

    def can_job_run(self, job):
        project_block = self._get_data_item(self.PROJECT_UPDATES, job.project_id)
        if not project_block[0]:
            return project_block
        project_block = self._get_data_item(self.INVENTORY_UPDATES, job.inventory_id)
        if not project_block[0]:
            return project_block
        if job.allow_simultaneous is False:
                return self._get_data_item(self.JOB_TEMPLATE_JOBS, job.job_template_id)
        return (True, None)

    def can_workflow_job_run(self, job):
        if job.allow_simultaneous:
            return (True, None)
        return self._get_data_item(self.WORKFLOW_JOB_TEMPLATES_JOBS, job.workflow_job_template_id)

    def can_system_job_run(self):
        return self.data[self.SYSTEM_JOB]

    def can_ad_hoc_command_run(self, job):
        return self._get_data_item(self.INVENTORY_UPDATES, job.inventory_id)

    def can_task_run(self, job):
        if type(job) is ProjectUpdate:
            return self.can_project_update_run(job)
        elif type(job) is InventoryUpdate:
            return self.can_inventory_update_run(job)
        elif type(job) is Job:
            return self.can_job_run(job)
        elif type(job) is SystemJob:
            return self.can_system_job_run()
        elif type(job) is AdHocCommand:
            return self.can_ad_hoc_command_run(job)
        elif type(job) is WorkflowJob:
            return self.can_workflow_job_run(job)

    def add_job(self, job):
        if type(job) is ProjectUpdate:
            self.mark_project_update(job)
        elif type(job) is InventoryUpdate:
            self.mark_inventory_update(job)
            self.mark_inventory_source_update(job)
        elif type(job) is Job:
            self.mark_job_template_job(job)
        elif type(job) is WorkflowJob:
            self.mark_workflow_job(job)
        elif type(job) is SystemJob:
            self.mark_system_job(job)
        elif type(job) is AdHocCommand:
            self.mark_inventory_update(job)

    def add_jobs(self, jobs):
        for j in jobs:
            self.add_job(j)
