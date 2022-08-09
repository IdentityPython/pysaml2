## NOTICE

this is not accurate anymore and needs to be reworked.


## Release instructions

When releasing a new version, the following steps should be taken:

1. Make sure all automated tests pass.

2. Make sure the package metadata in `setup.py` is up-to-date. You can
   verify the information by re-generating the egg info:

   ```
   python setup.py egg_info
   ```

   and inspecting `src/pysaml2.egg-info/PKG-INFO`. You should also make sure
   that the long description renders as valid reStructuredText. You can
   do this by using the `rst2html.py` utility from [docutils]:

   ```
   python setup.py --long-description | rst2html > test.html
   ```

   If this will produce warning or errors, PyPI will be unable to render
   the long description nicely. It will treat it as plain text instead.

3. Update the version in the [VERSION] file and report the changes in
   [CHANGELOG.md] and commit the changes.:

   ```
   git add CHANGELOG.md
   git add VERSION
   git commit -v -s -m "Release version X.Y.Z"
   ```

4. Create a release [branch]:

   ```
   git branch vX.Y.Z
   ```

5. Create a release [tag]:

   ```
   git tag -a -s vX.Y.Z -m "Version X.Y.Z"
   ```

6. Push these changes to Github:

   ```
   git push --follow-tags origin vX.Y.Z
   git push --follow-tags origin vX.Y.Z:vX.Y.Z
   ```

7. Create a source and wheel distribution and upload it to PyPI:

   generate a source and wheel distribution at once
   ```
   python setup.py sdist bdist_wheel
   ```

   generated files are under dist/
   ```
   ls dist/
   ```

   upload release on test.pypi.org
   ```
   twine upload --repository-url https://test.pypi.org/legacy/ dist/pysaml2-X.Y.Z*
   ```

   then, upload release on official pypi.org
   ```
   twine upload dist/pysaml2-X.Y.Z*
   ```

8. Upload the documentation to PyPI. First you need to generate the html
   version of the documentation:

   ```
   cd docs/
   make clean
   make html
   cd _build/html
   zip -r pysaml2-docs.zip *
   ```

   Submit the generated pysaml2-docs.zip file.

9. Send an email to the pysaml2 list announcing this release


**Important:** Once released to PyPI or any other public download location,
a released egg may *never* be removed, even if it has proven to be a faulty
release ("brown bag release"). In such a case it should simply be superseded
immediately by a new, improved release.


  [VERSION]: https://github.com/IdentityPython/pysaml2/blob/master/VERSION
  [CHANGELOG.md]: https://github.com/IdentityPython/pysaml2/blob/master/CHANGELOG.md
  [docutils]: http://docutils.sourceforge.net/
  [branch]: https://git-scm.com/book/en/v2/Git-Branching-Branches-in-a-Nutshell
  [tag]: https://git-scm.com/book/en/v2/Git-Basics-Tagging#_annotated_tags
