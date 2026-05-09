# Release instructions

When releasing a new version, the following steps should be taken:

1. Make sure the package metadata in `pyproject.toml` is up-to-date.

    ```shell
    poetry check
    ```

2. Make sure all automated tests pass:

    ```shell
    poetry run pytest
    ```

3. Bump the version of the package

    ```shell
    poetry version -- X.Y.Z
    ```

4. Update the [CHANGELOG.md]

5. Commit and sign the changes:

    ```shell
    git add -u  # CHANGELOG.md pyproject.toml
    git commit -v -s -m "Release version X.Y.Z"
    ```

6. Create a signed release [tag]:

    ```shell
    git tag -a -s vX.Y.Z -m "Version X.Y.Z"
    ```

7. Push the changes and the release to Github:

    ```shell
    git push --follow-tags
    ```

8. Publish the release. Creating the GitHub release fires the
   `Publish to PyPI` and `Attach artifacts to GitHub release` workflows,
   which build the distributions, generate PEP 740 attestations, and
   upload to PyPI/TestPyPI via Trusted Publishing.

   Pre-release path (publishes to TestPyPI):

    ```shell
    gh release create v7.5.5rc1 --prerelease --title "v7.5.5rc1" --notes "Pre-release for CI" --target <target-branch>
    ```

   Full release path (publishes to PyPI):

    ```shell
    gh release create v7.5.5 --title "v7.5.5" --notes "Release" --target master
    ```

   Or via the UI: Releases -> Draft a new release ->  choose/create tag ->
   tick (or untick) "Set as a pre-release" -> Publish release.

9. Send an email to the pysaml2 list announcing this release

[VERSION]: https://github.com/IdentityPython/pysaml2/blob/master/VERSION
[CHANGELOG.md]: https://github.com/IdentityPython/pysaml2/blob/master/CHANGELOG.md
[docutils]: http://docutils.sourceforge.net/
[branch]: https://git-scm.com/book/en/v2/Git-Branching-Branches-in-a-Nutshell
[tag]: https://git-scm.com/book/en/v2/Git-Basics-Tagging#_annotated_tags
