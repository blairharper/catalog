# Catalog project

Back-end template for a simple catalog site, in this case to record UK government departments and respective ministers.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

Requires: Python 2 and Vagrant with sqlite

```
https://wiki.python.org/moin/BeginnersGuide/Download
https://www.vagrantup.com/
https://www.sqlite.org/index.html
```

### Installation & usage

Create a fork of the repository or manually save local copies of the code available at:


To create a fork using Github:

1. Navigate to the repository linked above
2. In the top-right corner of the page, click **Fork**
3. That's it!
4. For more see: https://help.github.com/articles/fork-a-repo/


To run:
1. First of all run the database_setup.py script using the command: `python database_setup.py`
2. Then execute the application with the command: `python application.py`
3. Navigate to:

```
https://localhost:5000
```
IMPORTANT: The first user that registers using the google login link will be granted admin privelages. This is a temporary workaround - no admin console has yet been developed to manage admin privelages, as that functionality is out of scope for this project. No styling has been provided - this is a back end project.
