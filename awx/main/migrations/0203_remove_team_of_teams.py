import logging
from collections import defaultdict

from django.db import migrations

from ansible_base.rbac.migrations._utils import give_permissions

logger = logging.getLogger('awx.main.migrations')


def consolidate_indirect_user_roles(apps, schema_editor):
    """
    A user should have a member role for every team they were indirectly
    a member of. ex. Team A is a member of Team B. All users in Team A
    previously were only members of Team A. They should now be members of
    Team A and Team B.
    """

    # get models for membership on teams
    RoleDefinition = apps.get_model('dab_rbac', 'RoleDefinition')
    RoleUserAssignment = apps.get_model('dab_rbac', 'RoleUserAssignment')
    RoleTeamAssignment = apps.get_model('dab_rbac', 'RoleTeamAssignment')
    Team = apps.get_model('main', 'Team')

    team_member_role = RoleDefinition.objects.get(name='Team Member')

    def get_team_to_team_relationships():
        """
        Find all team-to-team relationships where one team is a member of another.
        Returns a dict mapping parent_team_id -> [child_team_id, ...]
        """
        team_to_team_relationships = defaultdict(list)

        # Find all team assignments with the Team Member role
        team_assignments = RoleTeamAssignment.objects.filter(role_definition=team_member_role).select_related('team')

        for assignment in team_assignments:
            parent_team_id = int(assignment.object_id)
            child_team_id = assignment.team.id
            team_to_team_relationships[parent_team_id].append(child_team_id)

        return team_to_team_relationships

    def get_all_user_members_of_team(team_id, team_to_team_map, visited=None):
        """
        Recursively find all users who are members of a team, including through nested teams.
        """
        if visited is None:
            visited = set()

        if team_id in visited:
            return set()  # Avoid infinite recursion

        visited.add(team_id)
        all_users = set()

        # Get direct user assignments to this team
        user_assignments = RoleUserAssignment.objects.filter(role_definition=team_member_role, object_id=team_id).select_related('user')

        for assignment in user_assignments:
            all_users.add(assignment.user)

        # Get team-to-team assignments and recursively find their users
        child_team_ids = team_to_team_map.get(team_id, [])
        for child_team_id in child_team_ids:
            nested_users = get_all_user_members_of_team(child_team_id, team_to_team_map, visited.copy())
            all_users.update(nested_users)

        return all_users

    def remove_team_to_team_assignment(parent_team_id, child_team_id):
        """
        Remove team-to-team memberships.
        """
        parent_team = Team.objects.get(id=parent_team_id)
        child_team = Team.objects.get(id=child_team_id)

        # Remove all team-to-team RoleTeamAssignments
        RoleTeamAssignment.objects.filter(role_definition=team_member_role, object_id=parent_team_id, team=child_team).delete()

        # Check mirroring Team model for children under member_role
        parent_team.member_role.children.filter(object_id=child_team_id).delete()

    team_to_team_map = get_team_to_team_relationships()

    if not team_to_team_map:
        return  # No team-to-team relationships to consolidate

    # Get content type for Team - needed for give_permissions
    try:
        from django.contrib.contenttypes.models import ContentType

        team_content_type = ContentType.objects.get_for_model(Team)
    except ImportError:
        # Fallback if ContentType is not available
        ContentType = apps.get_model('contenttypes', 'ContentType')
        team_content_type = ContentType.objects.get_for_model(Team)

    # Get all users who should be direct members of a team
    for parent_team_id, child_team_ids in team_to_team_map.items():
        all_users = get_all_user_members_of_team(parent_team_id, team_to_team_map)

        # Create direct RoleUserAssignments for all users
        if all_users:
            give_permissions(apps=apps, rd=team_member_role, users=list(all_users), object_id=parent_team_id, content_type_id=team_content_type.id)

        # Mirror assignments to Team model
        parent_team = Team.objects.get(id=parent_team_id)
        for user in all_users:
            parent_team.member_role.members.add(user.id)

        # Remove all team-to-team assignments for parent team
        for child_team_id in child_team_ids:
            remove_team_to_team_assignment(parent_team_id, child_team_id)


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0202_convert_controller_role_definitions'),
    ]

    operations = [
        migrations.RunPython(consolidate_indirect_user_roles, migrations.RunPython.noop),
    ]
