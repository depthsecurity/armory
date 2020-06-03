# Notes on stuff for the Armory Django switchover


## Dependencies

```
pip install django
pip install django-picklefield
```

## manage.py commands

```
./manage.py createsuperuser
```

# Set up database

```
armory2-manage migrate
```

# Update DB schema

```
armory2-manage makemigrations
```

or

```
python -m armory2 manage makemigrations
```

`test`

## Other notes



# Running Armory2

## When installed

To launch Armory itself:

```
armory2 
```

To launch django manage:

```
armory2-manage
```

## When in the prior folder

To launch armory itself

```
python -m armory2 <options>
```

To launch django manage

```
python -m armory2 manage <options>
```
