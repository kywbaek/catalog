from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# some user
user1 = User(name="Yoda", email="yodaFakeAccount@gmail.com", picture="https://pbs.twimg.com/profile_images/224332937/yoda_face_400x400.jpg")
session.add(user1)
session.commit()

user2 = User(name="Wookiee", email="wookieeFakeAccount@gmail.com", picture="https://pbs.twimg.com/profile_images/447164622806585345/zY-ss2qz_400x400.jpeg")
session.add(user2)
session.commit()

# catalog for baseball
category1 = Category(name="Baseball")

session.add(category1)
session.commit()

item1 = Item(name="Baseball (ball)", description="The ball features a rubber or cork center, wrapped in yarn, and covered with two strips of white horsehide or cowhide, tightly stitched together.", user=user1, category=category1)

session.add(item1)
session.commit()

item2 = Item(name="Baseball bat", description="The baseball bat is a smooth wooden or metal club used in the sport of baseball to hit the ball after it is thrown by the pitcher.", user=user1, category=category1)

session.add(item2)
session.commit()

item3 = Item(name="Baseball glove", description="A baseball glove or mitt is a large leather glove worn by baseball players of the defending team, which assists players in catching and fielding balls hit by a batter or thrown by a teammate.", user=user1, category=category1)

session.add(item3)
session.commit()


# catalog for badminton
category2 = Category(name="Badminton")

session.add(category2)
session.commit()

item1 = Item(name="Racket", description="The racket is a sports implement consisting of a handled frame with an open hoop across which a network of strings or catgut is stretched tightly.", user=user2, category=category2)

session.add(item1)
session.commit()

item2 = Item(name="Shuttlecock", description="The shuttlecock is a high-drag projectile used in the sport of badminton. It has an open conical shape formed by feathers (or a synthetic alternative) embedded into a rounded cork (or rubber) base.", user=user2, category=category2)

session.add(item2)
session.commit()

item3 = Item(name="Net", description="The net, in its primary meaning, comprises fibers woven in a grid-like structure.", user=user2, category=category2)

session.add(item3)
session.commit()


# catalog for soccer
category3 = Category(name="Soccer")

session.add(category3)
session.commit()

item1 = Item(name="Soccer ball", description="The football, soccer ball, or association football ball is the ball used in the sport of association football.", user=user1, category=category3)

session.add(item1)
session.commit()

item2 = Item(name="Cleat", description="Football boots, called cleats or soccer shoes in North America, are an item of footwear worn when playing football. Those designed for grass pitches have studs on the outsole to aid grip.", user=user2, category=category3)

session.add(item2)
session.commit()

item3 = Item(name="Shin guard", description="The shin gaurd or shin pad is a piece of equipment worn on the front of a player's shin to protect them from injury.", user=user2, category=category3)

session.add(item3)
session.commit()


category4 = Category(name="Rock Climbing")

session.add(category4)
session.commit()

category5 = Category(name="Hiking")

session.add(category5)
session.commit()

category6 = Category(name="Swimming")

session.add(category6)
session.commit()

print "added categories & items!"
