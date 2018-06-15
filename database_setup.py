from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()


# Database table structure for storing user info
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    name = Column(String(250), nullable=False)
    admin = Column(Integer)


# Database table structure for storing dept info
class Department(Base):
    __tablename__ = 'department'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


# Database table structure for storing minister info
class Minister(Base):
    __tablename__ = 'minister'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    const = Column(String(250), nullable=False)
    dept_id = Column(Integer, ForeignKey('department.id'))
    department = relationship(Department)


# Set engine as sqlite and define db file name
engine = create_engine('sqlite:///govdeptministers.db')

# Create db
Base.metadata.create_all(engine)
