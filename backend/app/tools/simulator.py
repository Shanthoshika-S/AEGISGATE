
class ToolSimulator:

    def __init__(self):
        # Sample files stored only in memory.
        self.sample_files = {
            "report.txt": "AEGISGATE security test report.",
            "notes.txt": "This is a simulated confidential document.",
        }

    def execute(self, tool_name: str, operation: str, parameters: dict):

        if tool_name == "calculator":

            a = parameters.get("a")
            b = parameters.get("b")

            if not isinstance(a, (int, float)) or isinstance(a, bool):
                raise ValueError("Parameter 'a' must be a number.")

            if not isinstance(b, (int, float)) or isinstance(b, bool):
                raise ValueError("Parameter 'b' must be a number.")

            if operation == "add":
                return {"result": a + b}

            if operation == "subtract":
                return {"result": a - b}

        if tool_name == "file_reader":

            if operation == "read":
                filename = parameters.get("filename")

                if not isinstance(filename, str):
                    raise ValueError("A valid filename is required.")

                if filename not in self.sample_files:
                    raise ValueError("File not found.")

                return {
                    "filename": filename,
                    "content": self.sample_files[filename],
                }

        raise ValueError("Unsupported tool or operation.")
