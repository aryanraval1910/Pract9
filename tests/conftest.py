import os
import tempfile

# Must be set before app.main is imported so the tests use a throw-away DB.
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
