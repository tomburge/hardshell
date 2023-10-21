class GlobalStatus:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # Initialize our global data
            cls._instance.package_status = {}
        return cls._instance

    def update_package_status(self, package_name, status):
        self.package_status[package_name] = status
