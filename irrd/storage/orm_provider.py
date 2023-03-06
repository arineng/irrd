import sqlalchemy.orm as saorm
from asgiref.sync import sync_to_async
from sqlalchemy.exc import SQLAlchemyError

from irrd.storage.database_handler import DatabaseHandler


class ORMSessionProvider:
    def __init__(self):
        self.database_handler = DatabaseHandler()
        self.session = self._get_session()

    def _get_session(self):
        return saorm.Session(bind=self.database_handler._connection)

    def get_database_handler(self):
        if not self.database_handler:
            self.database_handler = DatabaseHandler()
        return self.database_handler

    def commit_close(self):
        self.session.commit()
        self.database_handler.commit()
        self.session.close()
        self.database_handler.close()

    @sync_to_async
    def run(self, target):
        return self.run_sync(target)

    def run_sync(self, target):
        try:
            return target()
        except saorm.exc.NoResultFound:
            return None
        except SQLAlchemyError:
            self.get_database_handler().refresh_connection()
            target.__self__.session = self.session = self._get_session()
            return target()
