*************************
PySAML2 - SAML2 in Python
*************************

:Version: see VERSION_
:Documentation: https://pysaml2.readthedocs.io/

.. image:: https://api.travis-ci.org/IdentityPython/pysaml2.png?branch=master
    :target: https://travis-ci.org/IdentityPython/pysaml2

.. image:: https://img.shields.io/pypi/pyversions/pysaml2.svg
    :target: https://pypi.org/project/pysaml2/

.. image:: https://img.shields.io/pypi/v/pysaml2.svg
    :target: https://pypi.org/project/pysaml2/


PySAML2 is a pure python implementation of SAML Version 2 Standard. It contains
all necessary pieces for building a SAML2 service provider or an identity
provider. The distribution contains examples of both. Originally written to
work in a WSGI environment there are extensions that allow you to use it with
other frameworks.


Top Hat fork
============

This is a Top-Hat-specific fork of PySAML2. It's published manually to JFrog and consumed by THM.

How to package a new version
----------------------------

* On your branch, update the VERSION file - our convention seems to be ``<PySAML2 base version>-N`` where ``N`` is the number of TopHat's revision on top of the upstream version. E.g. ``4.6.5-2`` is the second revision since merging the upstream ``4.6.5`` version.
* Create a virtualenv to build the package in
    - ``python3 -m venv <some name>``
    - ``. <some name>/bin/activate``
* In the venv, ``python setup.py bdist_wheel --universal``
* Find the wheel file in ``dist/`` folder

How to QA your changes
----------------------

* ``docker cp`` the wheel file generated above into your development THM container
* ``th shell thm`` to enter the container
* ``pip list | grep pysaml`` - note the currently installed version
* ``pip uninstall pysaml2-tophat``
* ``re`` - this step may be excessive, but confirm that THM either won't start or SSO is broken. This will guarantee that when you install the new version, it's the new version that's running.
* ``pip install <path to wheel file>``
* ``pip list`` - confirm the new version is installed
* ``re`` and QA

How to deploy a new version
---------------------------

* Merge your branch to master
* Create a new Github release using the version convention described above
* Attach the wheel file to the release assets for posterity
* Get a member of ``@platform_help_me`` to upload the wheel file to JFrog for you
* Start a new THM branch
* Update the version of ``pysaml2-tophat`` in ``requirements_common.txt``. It won't be exactly the tag you used. E.g. if you put ``4.6.5-2`` in the VERSION file, you should put ``4.6.5.post2`` here. It should match part of the wheel file name.
* ``th shell thm`` to enter your dev container
* ``pip list | grep pysaml`` - note the currently installed version
* ``pip uninstall pysaml2-tophat``
* ``re`` - this step may be excessive, but confirm that THM either won't start or SSO is broken. This will guarantee that when you install the new version, it's the new version that's running.
* ``pip install -r requirements.txt``
* ``pip list`` - confirm the new version is installed
* ``re`` and smoke test
* Merge THM branch


Testing
=======

PySAML2 uses the pytest_ framework for testing. To run the tests on your
system's version of python:

1. Create and activate a virtualenv_
2. Inside the virtualenv_, install the dependencies needed for testing
   :code:`pip install -r tests/test-requirements.txt`
3. Run the tests :code:`py.test tests`

To run tests in multiple python environments, you can use pyenv_ with tox_.


Please contribute!
==================

To help out, you could:

1. Test and report any bugs or other difficulties.
2. Implement missing features.
3. Write more unit tests.

**If you have the time and inclination I'm looking for Collaborators**


.. _VERSION: VERSION
.. _pytest: https://docs.pytest.org/en/latest/
.. _virtualenv: https://virtualenv.pypa.io/en/stable/
.. _pyenv: https://github.com/yyuu/pyenv
.. _tox: https://tox.readthedocs.io/en/latest/
