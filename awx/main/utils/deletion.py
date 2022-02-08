from collections import Counter, defaultdict, OrderedDict
from itertools import chain
from django.db.models.deletion import (
    DO_NOTHING,
    CASCADE,
    Collector,
    ProtectedError,
    RestrictedError,
    get_candidate_relations_to_delete,
)
from django.db import transaction
from django.db.models import sql


def pre_delete(self):
    """Delete the records in the current QuerySet."""
    self._not_support_combined_queries('delete')
    assert not self.query.is_sliced, "Cannot use 'limit' or 'offset' with delete."

    if self._fields is not None:
        raise TypeError("Cannot call delete() after .values() or .values_list()")

    del_query = self._chain()

    # The delete is actually 2 queries - one to find related objects,
    # and one to delete. Make sure that the discovery of related
    # objects is performed on the same database as the deletion.
    del_query._for_write = True

    # Disable non-supported fields.
    del_query.query.select_for_update = False
    del_query.query.select_related = False
    del_query.query.clear_ordering(force_empty=True)
    return del_query


def bulk_related_objects(field, objs, using):
    # This overrides the method in django.contrib.contenttypes.fields.py
    """
    Return all objects related to ``objs`` via this ``GenericRelation``.
    """
    return field.remote_field.model._base_manager.db_manager(using).filter(
        **{
            "%s__pk"
            % field.content_type_field_name: ContentType.objects.db_manager(using).get_for_model(field.model, for_concrete_model=field.for_concrete_model).pk,
            "%s__in" % field.object_id_field_name: list(objs.values_list('pk', flat=True)),
        }
    )


class AWXCollector(Collector):
    def add(self, objs, source=None, nullable=False, reverse_dependency=False):
        """
        Add 'objs' to the collection of objects to be deleted.  If the call is
        the result of a cascade, 'source' should be the model that caused it,
        and 'nullable' should be set to True if the relation can be null.

        Return a list of all objects that were not already collected.
        """
        if not objs.exists():
            return objs
        model = objs.model
        self.data.setdefault(model, [])
        self.data[model].append(objs)
        # Nullable relationships can be ignored -- they are nulled out before
        # deleting, and therefore do not affect the order in which objects have
        # to be deleted.
        if source is not None and not nullable:
            if reverse_dependency:
                source, model = model, source
            self.dependencies.setdefault(source._meta.concrete_model, set()).add(model._meta.concrete_model)
        return objs

    def add_field_update(self, field, value, objs):
        """
        Schedule a field update. 'objs' must be a homogeneous iterable
        collection of model instances (e.g. a QuerySet).
        """
        if not objs.exists():
            return
        model = objs.model
        self.field_updates.setdefault(model, {})
        self.field_updates[model].setdefault((field, value), [])
        self.field_updates[model][(field, value)].append(objs)

    def collect(
        self, objs, source=None, nullable=False, collect_related=True, source_attr=None, reverse_dependency=False, keep_parents=False, fail_on_restricted=True
    ):
        """
        Add 'objs' to the collection of objects to be deleted as well as all
        parent instances.  'objs' must be a homogeneous iterable collection of
        model instances (e.g. a QuerySet).  If 'collect_related' is True,
        related objects will be handled by their respective on_delete handler.

        If the call is the result of a cascade, 'source' should be the model
        that caused it and 'nullable' should be set to True, if the relation
        can be null.

        If 'reverse_dependency' is True, 'source' will be deleted before the
        current model, rather than after. (Needed for cascading to parent
        models, the one case in which the cascade follows the forwards
        direction of an FK rather than the reverse direction.)

        If 'keep_parents' is True, data of parent model's will be not deleted.

        If 'fail_on_restricted' is False, error won't be raised even if it's
        prohibited to delete such objects due to RESTRICT, that defers
        restricted object checking in recursive calls where the top-level call
        may need to collect more objects to determine whether restricted ones
        can be deleted.
        """

        if hasattr(objs, 'polymorphic_disabled'):
            objs.polymorphic_disabled = True

        if self.can_fast_delete(objs):
            self.fast_deletes.append(objs)
            return
        new_objs = self.add(objs, source, nullable, reverse_dependency=reverse_dependency)
        if not new_objs:
            return

        model = new_objs[0].__class__

        if not keep_parents:
            # Recursively collect concrete model's parent models, but not their
            # related objects. These will be found by meta.get_fields()
            concrete_model = model._meta.concrete_model
            for ptr in concrete_model._meta.parents.keys():
                if ptr:
                    parent_objs = ptr.objects.filter(pk__in=new_objs.values_list('pk', flat=True))
                    self.collect(parent_objs, source=model, collect_related=False, reverse_dependency=True)

        if not collect_related:
            return

        if keep_parents:
            parents = set(model._meta.get_parent_list())
        model_fast_deletes = defaultdict(list)
        protected_objects = defaultdict(list)
        for related in get_candidate_relations_to_delete(model._meta):
            # Preserve parent reverse relationships if keep_parents=True.
            if keep_parents and related.model in parents:
                continue
            field = related.field
            if field.remote_field.on_delete == DO_NOTHING:
                continue
            related_model = related.related_model
            if self.can_fast_delete(related_model, from_field=field):
                model_fast_deletes[related_model].append(field)
                continue
            batches = self.get_del_batches(new_objs, [field])
            for batch in batches:
                sub_objs = self.related_objects(related_model, [field], batch)
                # Non-referenced fields can be deferred if no signal receivers
                # are connected for the related model as they'll never be
                # exposed to the user. Skip field deferring when some
                # relationships are select_related as interactions between both
                # features are hard to get right. This should only happen in
                # the rare cases where .related_objects is overridden anyway.
                if not (sub_objs.query.select_related or self._has_signal_listeners(related_model)):
                    referenced_fields = set(
                        chain.from_iterable(
                            (rf.attname for rf in rel.field.foreign_related_fields) for rel in get_candidate_relations_to_delete(related_model._meta)
                        )
                    )
                    sub_objs = sub_objs.only(*tuple(referenced_fields))
                if sub_objs:
                    try:
                        field.remote_field.on_delete(self, field, sub_objs, self.using)
                    except ProtectedError as error:
                        key = "'%s.%s'" % (field.model.__name__, field.name)
                        protected_objects[key] += error.protected_objects
        if protected_objects:
            raise ProtectedError(
                'Cannot delete some instances of model %r because they are '
                'referenced through protected foreign keys: %s.'
                % (
                    model.__name__,
                    ', '.join(protected_objects),
                ),
                set(chain.from_iterable(protected_objects.values())),
            )
        for related_model, related_fields in model_fast_deletes.items():
            batches = self.get_del_batches(new_objs, related_fields)
            for batch in batches:
                sub_objs = self.related_objects(related_model, related_fields, batch)
                self.fast_deletes.append(sub_objs)
        for field in model._meta.private_fields:
            if hasattr(field, 'bulk_related_objects'):
                # It's something like generic foreign key.
                sub_objs = field.bulk_related_objects(new_objs, self.using)
                self.collect(sub_objs, source=model, nullable=True, fail_on_restricted=False)

        if fail_on_restricted:
            # Raise an error if collected restricted objects (RESTRICT) aren't
            # candidates for deletion also collected via CASCADE.
            for related_model, instances in self.data.items():
                self.clear_restricted_objects_from_set(related_model, instances)
            for qs in self.fast_deletes:
                self.clear_restricted_objects_from_queryset(qs.model, qs)
            if self.restricted_objects.values():
                restricted_objects = defaultdict(list)
                for related_model, fields in self.restricted_objects.items():
                    for field, objs in fields.items():
                        if objs:
                            key = "'%s.%s'" % (related_model.__name__, field.name)
                            restricted_objects[key] += objs
                if restricted_objects:
                    raise RestrictedError(
                        'Cannot delete some instances of model %r because '
                        'they are referenced through restricted foreign keys: '
                        '%s.'
                        % (
                            model.__name__,
                            ', '.join(restricted_objects),
                        ),
                        set(chain.from_iterable(restricted_objects.values())),
                    )

    def delete(self):

        # if possible, bring the models in an order suitable for databases that
        # don't support transactions or cannot defer constraint checks until the
        # end of a transaction.
        self.sort()
        # number of objects deleted for each model label
        deleted_counter = Counter()

        # collect pk_list before deletion (once things start to delete
        # queries might not be able to retreive pk list)
        del_dict = OrderedDict()
        for model, instances in self.data.items():
            del_dict.setdefault(model, [])
            for inst in instances:
                del_dict[model] += list(inst.values_list('pk', flat=True))

        # Optimize for the case with a single obj and no dependencies
        if len(self.data) == 1 and len(instances) == 1:
            instance = list(instances)[0]
            if self.can_fast_delete(instance):
                with transaction.mark_for_rollback_on_error(self.using):
                    count = sql.DeleteQuery(model).delete_batch([instance.pk], self.using)
                setattr(instance, model._meta.pk.attname, None)
                return count, {model._meta.label: count}

        with transaction.atomic(using=self.using, savepoint=False):

            # fast deletes
            for qs in self.fast_deletes:
                count = qs._raw_delete(using=self.using)
                deleted_counter[qs.model._meta.label] += count

            # update fields
            for model, instances_for_fieldvalues in self.field_updates.items():
                for (field, value), instances in instances_for_fieldvalues.items():
                    for inst in instances:
                        query = sql.UpdateQuery(model)
                        query.update_batch(inst.values_list('pk', flat=True), {field.name: value}, self.using)

            # delete instances
            for model, pk_list in del_dict.items():
                query = sql.DeleteQuery(model)
                count = query.delete_batch(pk_list, self.using)
                deleted_counter[model._meta.label] += count

        return sum(deleted_counter.values()), dict(deleted_counter)
