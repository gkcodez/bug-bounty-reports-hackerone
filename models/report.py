class Report:
    def __init__(
            self,
            title: str = "",
            url: str = "",
            program: str = "",
            asset_type: str = "",
            bounty: float = 0.0,
            vulnerability_type: str = "",
            severity: str = "",
            state: str = "",
            upvotes: int = 0,
            submitted_at: str = "",
            disclosed_at: str = ""
            ):
        self.title = title
        self.url = url
        self.program = program
        self.asset_type = asset_type
        self.bounty = bounty
        self.vulnerability_type = vulnerability_type
        self.severity = severity
        self.state = state
        self.upvotes = upvotes
        self.submitted_at = submitted_at
        self.disclosed_at = disclosed_at

    def to_dict(self):
        pass

