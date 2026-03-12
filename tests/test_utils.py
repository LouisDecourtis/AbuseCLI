from abusecli.utils import parse_duration


class TestParseDuration:
    def test_days(self):
        assert parse_duration("7d") == 7 * 86400

    def test_hours(self):
        assert parse_duration("12h") == 12 * 3600

    def test_minutes(self):
        assert parse_duration("30m") == 30 * 60

    def test_invalid(self):
        assert parse_duration("abc") is None

    def test_invalid_unit(self):
        assert parse_duration("5s") is None

    def test_zero(self):
        assert parse_duration("0d") == 0
