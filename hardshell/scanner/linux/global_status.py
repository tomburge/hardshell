# class GlobalStatus:
#     _instance = None

#     def __new__(cls):
#         if cls._instance is None:
#             cls._instance = super().__new__(cls)
#             # Initialize our global data
#             cls._instance.package_status = {}
#             cls._instance.module_deny_status = {}
#             cls._instance.module_load_status = {}
#         return cls._instance

#     def update_package_status(self, package_name, status):
#         self.package_status[package_name] = status

#     def update_module_deny_status(self, module_name, status):
#         self.module_deny_status[module_name] = status

#     def update_module_load_status(self, module_name, status):
#         self.module_load_status[module_name] = status


# global_status = GlobalStatus()

global_status = {"package": {}, "kernel": {}}
