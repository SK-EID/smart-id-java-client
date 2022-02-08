# Guidelines for developers of this library

## Main principles

### Use as few external dependencies as possible

Always prefer the functionality built into Java in favor of Apache Commons/Lang/Codec etc.

You can check the effective dependency tree:
mvn dependency:tree -Dscope=compile

### Keep 3rd party licenses file updated

If you add or remove dependencies then don't forget to run

mvn license:add-third-party

to update the file: LICENSE.3RD-PARTY 