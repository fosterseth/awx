import pytest
import datetime
import dateutil

from django.utils.timezone import now

from awx.main.models.schedules import _fast_forward_rrule, Schedule
from dateutil.rrule import HOURLY, MINUTELY, MONTHLY

REF_DT = datetime.datetime(2026, 4, 16, tzinfo=datetime.timezone.utc)

# This rrule has BYHOUR=1,5,9,13,17,21 (all 1 mod 4) with INTERVAL=4.
# It triggers ValueError in the old UTC-based fast-forward when the anchor
# is in a different DST period than the original dtstart.
RRULE_BYHOUR_DST = 'DTSTART;TZID=America/New_York:20251211T130000 RRULE:FREQ=HOURLY;INTERVAL=4;WKST=MO;BYDAY=MO,TU,WE,TH,FR;BYHOUR=1,5,9,13,17,21;BYMINUTE=0'


def _get_anchor(rrulestr, ref_dt):
    """Helper to compute a valid anchor_dt (a real occurrence near ref_dt)."""
    orig = dateutil.rrule.rrulestr(rrulestr, forceset=True)
    anchor = orig.before(ref_dt, inc=True)
    if anchor is None:
        anchor = orig.after(ref_dt)
    return anchor


@pytest.mark.parametrize(
    'rrulestr',
    [
        pytest.param('DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=MINUTELY;INTERVAL=5', id='every-5-min'),
        pytest.param('DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=HOURLY;INTERVAL=5', id='every-5-hours'),
        pytest.param('DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=YEARLY;INTERVAL=5', id='every-5-years'),
        pytest.param(
            'DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=MINUTELY;INTERVAL=5;WKST=SU;BYMONTH=2,3;BYMONTHDAY=18;BYHOUR=5;BYMINUTE=35;BYSECOND=0',
            id='every-5-minutes-at-5:35:00-am-on-the-18th-day-of-feb-or-march-with-week-starting-on-sundays',
        ),
        pytest.param(
            'DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=HOURLY;INTERVAL=5;WKST=SU;BYMONTH=2,3;BYHOUR=5',
            id='every-5-hours-at-5-am-in-feb-or-march-with-week-starting-on-sundays',
        ),
    ],
)
def test_fast_forwarded_rrule_matches_original_occurrence(rrulestr):
    '''
    Assert that the resulting fast forwarded date is included in the original rrule
    occurrence list
    '''
    anchor = _get_anchor(rrulestr, REF_DT)
    rruleset = Schedule.rrulestr(rrulestr, anchor_dt=anchor)

    gen = rruleset.xafter(REF_DT, count=200)
    occurrences = [i for i in gen]

    orig_rruleset = dateutil.rrule.rrulestr(rrulestr, forceset=True)
    gen = orig_rruleset.xafter(REF_DT, count=200)
    orig_occurrences = [i for i in gen]

    assert occurrences == orig_occurrences


@pytest.mark.parametrize(
    'ref_dt',
    [
        pytest.param(datetime.datetime(2024, 12, 1, 0, 0, tzinfo=datetime.timezone.utc), id='ref-dt-out-of-dst'),
        pytest.param(datetime.datetime(2024, 6, 1, 0, 0, tzinfo=datetime.timezone.utc), id='ref-dt-in-dst'),
    ],
)
@pytest.mark.parametrize(
    'rrulestr',
    [
        pytest.param('DTSTART;TZID=America/New_York:20240118T200000 RRULE:FREQ=MINUTELY;INTERVAL=10', id='rrule-out-of-dst'),
        pytest.param('DTSTART;TZID=America/New_York:20240318T000000 RRULE:FREQ=MINUTELY;INTERVAL=10', id='rrule-in-dst'),
        pytest.param(
            'DTSTART;TZID=Europe/Lisbon:20230703T005800 RRULE:INTERVAL=10;FREQ=MINUTELY;BYHOUR=9,10,11,12,13,14,15,16,17,18,19,20,21', id='rrule-in-dst-by-hour'
        ),
        pytest.param('DTSTART;TZID=America/New_York:20240118T200000 RRULE:FREQ=HOURLY;INTERVAL=5', id='rrule-hourly-out-of-dst'),
    ],
)
def test_fast_forward_across_dst(rrulestr, ref_dt):
    '''
    Ensure fast forward works across daylight savings boundaries
    "in dst" means between March and November
    "out of dst" means between November and March the following year

    Assert that the resulting fast forwarded date is included in the original rrule
    occurrence list
    '''
    anchor = _get_anchor(rrulestr, ref_dt)
    rruleset = Schedule.rrulestr(rrulestr, anchor_dt=anchor)

    gen = rruleset.xafter(ref_dt, count=200)
    occurrences = [i for i in gen]

    orig_rruleset = dateutil.rrule.rrulestr(rrulestr, forceset=True)
    gen = orig_rruleset.xafter(ref_dt, count=200)
    orig_occurrences = [i for i in gen]

    assert occurrences == orig_occurrences


def test_fast_forward_rrule_hours():
    '''
    Generate an rrule for each hour of the day

    Assert that the resulting fast forwarded date is included in the original rrule
    occurrence list
    '''
    rrulestr_prefix = 'DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=HOURLY;'
    for interval in range(1, 24):
        rrulestr = f"{rrulestr_prefix}INTERVAL={interval}"
        anchor = _get_anchor(rrulestr, REF_DT)
        rruleset = Schedule.rrulestr(rrulestr, anchor_dt=anchor)

        gen = rruleset.xafter(REF_DT, count=200)
        occurrences = [i for i in gen]

        orig_rruleset = dateutil.rrule.rrulestr(rrulestr, forceset=True)
        gen = orig_rruleset.xafter(REF_DT, count=200)
        orig_occurrences = [i for i in gen]

        assert occurrences == orig_occurrences


def test_multiple_rrules():
    '''
    Create an rruleset that contains multiple rrules and an exrule
    rruleA: freq HOURLY interval 5, dtstart should be fast forwarded
    rruleB: freq HOURLY interval 7, dtstart should be fast forwarded
    rruleC: freq MONTHLY interval 1, dtstart should not be fast forwarded
    exruleA: freq HOURLY interval 5, dtstart should be fast forwarded
    '''
    rrulestr = '''DTSTART;TZID=America/New_York:20201118T200000
                RRULE:FREQ=HOURLY;INTERVAL=5
                RRULE:FREQ=HOURLY;INTERVAL=7
                RRULE:FREQ=MONTHLY
                EXRULE:FREQ=HOURLY;INTERVAL=5;BYDAY=MO,TU,WE'''
    anchor = _get_anchor(rrulestr, REF_DT)
    rruleset = Schedule.rrulestr(rrulestr, anchor_dt=anchor)

    rruleA, rruleB, rruleC = rruleset._rrule

    # the freq=monthly rrule's dtstart should not have changed
    dateutil_rruleset = dateutil.rrule.rrulestr(rrulestr, forceset=True)
    assert rruleC._dtstart == dateutil_rruleset._rrule[2]._dtstart

    gen = rruleset.xafter(REF_DT, count=200)
    occurrences = [i for i in gen]

    orig_rruleset = dateutil.rrule.rrulestr(rrulestr, forceset=True)
    gen = orig_rruleset.xafter(REF_DT, count=200)
    orig_occurrences = [i for i in gen]

    assert occurrences == orig_occurrences


def test_no_anchor_does_not_fast_forward():
    '''When anchor_dt is None, the rrule should not be modified.'''
    dtstart = REF_DT - datetime.timedelta(days=30)
    rrule = dateutil.rrule.rrule(freq=HOURLY, interval=7, dtstart=dtstart)
    new_rrule = _fast_forward_rrule(rrule, anchor_dt=None)
    assert new_rrule == rrule


def test_rrule_with_count_does_not_fast_forward():
    rrule = dateutil.rrule.rrule(freq=MINUTELY, interval=5, count=1, dtstart=REF_DT)
    anchor = REF_DT + datetime.timedelta(hours=1)
    assert rrule == _fast_forward_rrule(rrule, anchor_dt=anchor)


@pytest.mark.parametrize(
    'freq',
    [
        pytest.param(MONTHLY, id="freq-MONTHLY"),
    ],
)
def test_non_hourly_minutely_does_not_fast_forward(freq):
    '''
    Assert that non-HOURLY/MINUTELY rrules are not fast forwarded
    '''
    dtstart = REF_DT - datetime.timedelta(days=30)
    rrule = dateutil.rrule.rrule(freq=freq, interval=1, dtstart=dtstart)
    anchor = REF_DT
    assert rrule == _fast_forward_rrule(rrule, anchor_dt=anchor)


@pytest.mark.parametrize(
    'ref_dt',
    [
        pytest.param(datetime.datetime(2026, 1, 15, 14, 0, 0, tzinfo=datetime.timezone.utc), id='during-EST'),
        pytest.param(datetime.datetime(2026, 7, 1, 14, 0, 0, tzinfo=datetime.timezone.utc), id='during-EDT'),
        pytest.param(datetime.datetime(2026, 3, 8, 8, 0, 0, tzinfo=datetime.timezone.utc), id='EST-to-EDT-boundary'),
        pytest.param(datetime.datetime(2026, 11, 1, 6, 0, 0, tzinfo=datetime.timezone.utc), id='EDT-to-EST-boundary'),
    ],
)
def test_fast_forward_byhour_across_dst(ref_dt):
    '''
    An HOURLY rrule with BYHOUR constraints where all BYHOUR values share the
    same residue mod INTERVAL should produce valid occurrences after fast-forward,
    regardless of whether ref_dt is in EST or EDT.
    '''
    anchor = _get_anchor(RRULE_BYHOUR_DST, ref_dt)
    rruleset = Schedule.rrulestr(RRULE_BYHOUR_DST, anchor_dt=anchor)

    gen = rruleset.xafter(ref_dt, count=20)
    occurrences = list(gen)

    orig_rruleset = dateutil.rrule.rrulestr(RRULE_BYHOUR_DST, forceset=True)
    gen = orig_rruleset.xafter(ref_dt, count=20)
    orig_occurrences = list(gen)

    assert occurrences == orig_occurrences


def test_fast_forward_byhour_dst_does_not_raise():
    '''
    Directly test _fast_forward_rrule with the problematic BYHOUR rrule during
    EDT. Before the fix this raised ValueError.
    '''
    from dateutil.tz import gettz

    tz = gettz('America/New_York')
    dtstart = datetime.datetime(2025, 12, 11, 13, 0, tzinfo=tz)
    original = dateutil.rrule.rrule(
        freq=HOURLY,
        interval=4,
        dtstart=dtstart,
        byhour=(1, 5, 9, 13, 17, 21),
        byminute=(0,),
        byweekday=(0, 1, 2, 3, 4),  # MO-FR
    )

    # Use a valid occurrence during EDT as the anchor
    ref_dt_edt = datetime.datetime(2026, 7, 1, 14, 0, 0, tzinfo=datetime.timezone.utc)
    anchor = original.before(ref_dt_edt, inc=True)
    result = _fast_forward_rrule(original, anchor_dt=anchor)

    # The fast-forwarded rrule must produce valid occurrences
    occurrences = list(result.xafter(ref_dt_edt, count=5))
    assert len(occurrences) == 5

    # All occurrence hours must be in the BYHOUR set
    for occ in occurrences:
        local_hour = occ.astimezone(tz).hour
        assert local_hour in {1, 5, 9, 13, 17, 21}, f"Hour {local_hour} not in BYHOUR set"


@pytest.mark.parametrize(
    'rrulestr',
    [
        pytest.param('DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=HOURLY;INTERVAL=5', id='hourly-5'),
        pytest.param('DTSTART;TZID=America/New_York:20201118T200000 RRULE:FREQ=MINUTELY;INTERVAL=10', id='minutely-10'),
        pytest.param(RRULE_BYHOUR_DST, id='hourly-byhour'),
    ],
)
def test_future_anchor_returns_anchor_as_next_occurrence(rrulestr):
    '''
    When anchor_dt is in the future (the normal case — the schedule hasn't
    fired yet), calling .after(now) on the fast-forwarded rruleset should
    return the same value as calling .after(now) on the original rruleset.

    This mirrors the behavior in update_computed_fields_no_save where
    anchor_dt=self.next_run and next_run_actual=future_rs.after(now()).
    '''
    past_dt = datetime.datetime(2024, 6, 1, 0, 0, tzinfo=datetime.timezone.utc)

    orig_rruleset = dateutil.rrule.rrulestr(rrulestr, forceset=True)
    future_next_run = orig_rruleset.after(past_dt)

    anchor = future_next_run
    fast_forwarded = Schedule.rrulestr(rrulestr, anchor_dt=anchor)

    result = fast_forwarded.after(past_dt)
    expected = orig_rruleset.after(past_dt)
    assert result == expected
