from abusecli.cli import create_parser


class TestCLIParser:
    def test_check_command(self):
        parser = create_parser()
        args = parser.parse_args(["check", "--ips", "1.1.1.1", "8.8.8.8"])
        assert args.command == "check"
        assert args.ips == ["1.1.1.1", "8.8.8.8"]

    def test_check_with_file(self):
        parser = create_parser()
        args = parser.parse_args(["check", "--file", "ips.txt"])
        assert args.command == "check"
        assert args.file == "ips.txt"

    def test_check_with_filters(self):
        parser = create_parser()
        args = parser.parse_args(
            [
                "check",
                "--ips",
                "1.1.1.1",
                "--risk-level",
                "critical",
                "--score",
                "75",
                "--country-code",
                "CN",
                "--is-tor",
                "--remove-private",
                "--remove-whitelisted",
            ]
        )
        assert args.risk_level == "critical"
        assert args.score == 75
        assert args.country_code == "CN"
        assert args.is_tor is True
        assert args.remove_private is True
        assert args.remove_whitelisted is True

    def test_check_with_enrich(self):
        parser = create_parser()
        args = parser.parse_args(["check", "--ips", "1.1.1.1", "--enrich"])
        assert args.enrich is True

    def test_check_with_export(self):
        parser = create_parser()
        args = parser.parse_args(
            ["check", "--ips", "1.1.1.1", "--export", "csv", "json"]
        )
        assert args.export == ["csv", "json"]

    def test_analyze_command(self):
        parser = create_parser()
        args = parser.parse_args(["analyze", "/var/log/auth.log"])
        assert args.command == "analyze"
        assert args.log_file == "/var/log/auth.log"

    def test_report_command(self):
        parser = create_parser()
        args = parser.parse_args(
            [
                "report",
                "--ip",
                "1.2.3.4",
                "--categories",
                "18,22",
                "--comment",
                "SSH brute force",
            ]
        )
        assert args.command == "report"
        assert args.ip == "1.2.3.4"
        assert args.categories == "18,22"
        assert args.comment == "SSH brute force"

    def test_quota_command(self):
        parser = create_parser()
        args = parser.parse_args(["quota"])
        assert args.command == "quota"

    def test_load_command(self):
        parser = create_parser()
        args = parser.parse_args(["load", "--source", "results.csv"])
        assert args.command == "load"
        assert args.source == "results.csv"

    def test_cache_stats(self):
        parser = create_parser()
        args = parser.parse_args(["cache", "stats"])
        assert args.command == "cache"
        assert args.cache_action == "stats"

    def test_cache_clear(self):
        parser = create_parser()
        args = parser.parse_args(["cache", "clear", "--older-than", "7d"])
        assert args.command == "cache"
        assert args.cache_action == "clear"
        assert args.older_than == "7d"

    def test_global_token(self):
        parser = create_parser()
        args = parser.parse_args(["--token", "mykey", "quota"])
        assert args.token == "mykey"

    def test_global_no_cache(self):
        parser = create_parser()
        args = parser.parse_args(["--no-cache", "check", "--ips", "1.1.1.1"])
        assert args.no_cache is True
