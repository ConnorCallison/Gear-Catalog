import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = 'users'
	name = Column(String(80), nullable = False)
	email = Column(String(80), nullable = False)
	picture = Column(String(250))
	id = Column(Integer, primary_key = True)

class Category(Base):
	__tablename__ = 'categories'
	name = Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	user_id = Column(Integer, ForeignKey('users.id'))
	user = relationship(User)

class Item(Base):
	__tablename__ = 'items'
	name = Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	price = Column(String(8))
	description = Column(String(300))
	picture = Column(String(250))
	category_id = Column(Integer, ForeignKey('categories.id'))
	category = relationship(Category)
	user_id = Column(Integer, ForeignKey('users.id'))
	user = relationship(User)

	@property
	def serialize(self):
		#returns object data in an easily seializble format
		return {
		'name' : self.name,
		'description' : self.description,
		'id' : self.id,
		'price' : self.price,
		'picture' : self.picture
		}

# End of file
engine = create_engine('sqlite:///item_catalog.db')
Base.metadata.create_all(engine)
