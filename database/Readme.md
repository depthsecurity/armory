## Database portion of the Mastertool

### Usage 
To use the database portion it is as simple as doing:
```
import database
from database.repositories import DomainRepository

db = database.create_database(connect_string)
## connect_string is the connection string for the database.

dr = DomainRepository(db)

# To either create object or get existing:
res = dr.find_or_create(domain='www.google.com')
## res is a tuple with a bool for if the object was created and the object

# To get all objects:
domains = dr.all()

# To commit writes to database (this must be done at least at end of run)
dr.commit()


```

Currently there are four Repositories: `BaseDomainRepository`, `DomainRepository`, `IPRepository`, and `CIDRRepository`.

Once you have the object created using the repository you can modify the object and when you want to update the object
simply run `object.save()`. You can also update the object with key word args for example:
```
cidr = CIDRRepository(db).find_or_create(cidr='123.123.123.0/23', org_name='Depth')

cidr.update(cidr='127.0.0.1/24')
```

Using this method will also save the object to the database in memory. At the end, you must ensure you commit the changes.

```
CIDRRepository(db).commit()
```
