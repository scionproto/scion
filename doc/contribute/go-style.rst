.. _go-style-guide:

**************
Go Style Guide
**************

Unless specified otherwise below, stick to golang's
`CodeReviewComments <https://github.com/golang/go/wiki/CodeReviewComments>`__.

Generally the code should be formatted with ``gofmt`` (checked by CI).

Lines must be at most 100 characters long (checked by CI via `lll`).

Naming
------

We use mixedCaps notation as recommended by `Effective Go
<https://golang.org/doc/effective_go.html>`__. The following rules apply (note
that a significant part of the code base uses other notations; these should be
refactored, however):

- Use ``sd`` or ``SD`` to refer to the SCION Daemon, not ``Sciond`` or ``SCIOND``.
- Use ``IfID`` or ``ifID`` for SCION Interface Identifiers, not ``IFID`` or ``InterfaceID``.
- Use ``Svc`` or ``svc`` for SCION Service Addresses, not ``SVC`` or ``Service``.
- Use ``TRC`` or ``trc`` for Trust Root Configurations, not ``Trc``.

Imports (checked by CI)
-----------------------

Imports are grouped (separated by empty line) in the following order:

* standard lib
* third-party packages
* our packages

Within each group the imports are alphabetically sorted.

Function declaration over multiple lines
----------------------------------------

If a function declaration uses more than 1 line the first line should be empty:

.. code-block:: go

    func usingMultipleLines(
        args string) error {

        // start the code here
    }

Abbreviations
-------------

For variable names common abbreviations should be preferred to full names, if
they are clear from the context, or used across the codebase.

Examples:

- ``Seg`` instead of ``Segment``
- ``Msger`` instead of ``Messenger``
- ``Sync`` instead of ``Synchronization``

Specialities
------------

goroutines should always call ``defer log.HandlePanic()`` as the first statement (checked by CI).

Logging
-------

* Use the SCION logging, i.e. import ``"github.com/scionproto/scion/go/lib/log"``.
* Do not use ``log.Root().New(...)``, instead use New directly: ``log.New(...)``.
* Keys should be snake case; use ``log.Debug("msg", "some_key", "foo")`` instead
  of ``log.Debug("msg", "someKey", "foo")`` or other variants.
* Try to not repeat key-value pairs in logging calls that are close-by; derive a
  new logging context instead (e.g., if multiple logging calls refer to a
  ``"request"`` for ``"Foo"``, create a sublogger with this context by calling
  ``newLogger = parentLogger.New("request", "Foo")`` and then use
  ``newLogger.Debug("x")``).
* If multiple logging lines need to be correlated for debugging, consider adding
  a debugging ID to them via ``log.NewDebugID``. Usually this is done together
  with the sub-logger pattern in the previous bullet.
* An empty ``log.New()`` has no impact and should be omitted.

Metrics
-------

For metrics implementation, see
`here <https://github.com/scionproto/scion/blob/master/doc/Metrics.md>`__.

