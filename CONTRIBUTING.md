# Contributing to wdk-serial-port

## Reaching Out

* If you have any issues or feature requests, feel free to open an Issue via GitHub.
* If you have issues related to security, or matters you wish to bring up personally, feel free to reach out directly
  via my contact details, found in my Github bio and profile.

## Code Guidelines

Todo: Develop more fledged out and consistent formatting and style guidelines.

### Safety

#### Safety Documentation

* All `unsafe` code blocks should be preceeded by a code comment, dictating why the block is actually safe.
* This currently has the side effect of some seemingly redundant comments, such as having a nullptr check followed up
  by a dereference, and a comment explaining that the nullptr check makes it safe to assume the type and validity.
  However this seems worth it at the moment, given the alternative leaves more room for ambiguity, and for potential
  unsafe usage to slip by.

#### Unsafe Functions

* To keep code as safe and clean as possible, writing unsafe functions is currently forbidden (until a valid use case
  arises).
* Functions that must be unsafe, such as completion routines, should wrap around a safe function. This is done so
  that unsafe blocks of code can be kept to a minimum, to ease documentation around their safety.
