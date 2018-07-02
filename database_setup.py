from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    """ Database table structure for storing user info """
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    name = Column(String(250), nullable=False)


class Department(Base):
    """  Database table structure for storing dept info """
    __tablename__ = 'department'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialise(self):
        """ Return object data in serialisable format """
        return {
            'name': self.name,
            'id': self.id,
        }


class Minister(Base):
    """  Database table structure for storing minister info """
    __tablename__ = 'minister'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    const = Column(String(250), nullable=False)
    dept_id = Column(Integer, ForeignKey('department.id'))
    department = relationship(Department)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialise(self):
        # Return object data in serialisable format
        return {
            'name': self.name,
            'constituency': self.const,
            'id': self.id,
            'dept_id': self.dept_id
        }


# Set engine as postgresql and define db file name
engine = create_engine('postgresql://ukgovcat:PASSWORD@localhost/ukgovcat')

# Create db
Base.metadata.create_all(engine)
