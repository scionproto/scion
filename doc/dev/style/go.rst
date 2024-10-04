**************
Go Style Guide
**************

Unless specified otherwise below, stick to golang's
`CodeReviewComments <https://github.com/golang/go/wiki/CodeReviewComments>`__.

Generally the code should be formatted with ``gofmt`` (checked by CI).

Lines must be at most 100 characters long (checked by CI via ``lll``).

Naming
------

We use mixedCaps notation as recommended by `Effective Go
<https://golang.org/doc/effective_go.html>`__. Perhaps unintuitively, Go
treats ``ID`` as an initialism, and we treat ``If`` as a word. The following
rules apply (note that a significant part of the code base uses other
notations; these should be refactored, however):

- Use ``sd`` or ``SD`` to refer to the SCION Daemon, not ``Sciond`` or ``SCIOND``.
- Use ``IfID`` or ``ifID`` for SCION Interface Identifiers, not ``IFID`` nor ``InterfaceID`` nor ``intfID``.
- Use ``IfIDSomething`` or ``ifIDSomething`` when concatenating ``ifID`` with ``something``.
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

If a function declaration uses more than 1 line, each parameter should be
declared on a separate line and the first line of the function body should be
empty:

.. code-block:: go

    func usingMultipleLines(
        foo int,
        bar []string,
        qux bool,
    ) error {

        // start the code here
    }

Abbreviations
-------------

For variable names common abbreviations should be preferred to full names, if
they are clear from the context, or used across the codebase.

Examples:

- ``Seg`` instead of ``Segment``
- ``Msgr`` instead of ``Messenger``
- ``Sync`` instead of ``Synchronization``

Specialities
------------

goroutines should always call ``defer log.HandlePanic()`` as the first statement (checked by CI).

Logging
-------

- To use logging, import ``"github.com/scionproto/scion/go/lib/log"``.
- The logging package supports three logging levels:

  - **Debug**: entries that are aimed only at developers, and include very low-level details.
    These should never be enabled on a production machine. Examples of such entries may include
    opening a socket, receiving a network message, or loading a file from the disk.
  - **Info**: entries that either contain high-level information about what the application
    is doing, or “errors” that are part of normal operation and have been handled by the code.
    Examples of such entries may include: issuing a new certificate for a client, having
    the authentication of an RPC call fail, or timing out when trying to connect to a server.
  - **Error**: entries about severe problems encountered by the application.
    The application might even need to terminate due to such an error. Example of such entries
    may include: the database is unreachable, the database schema is corrupted, or writing a file
    has failed due to insufficient disk space.

- Do not use ``log.Root().New(...)``, instead use New directly: ``log.New(...)``.
- Keys should be snake case; use ``log.Debug("msg", "some_key", "foo")`` instead
  of ``log.Debug("msg", "someKey", "foo")`` or other variants.
- Try to not repeat key-value pairs in logging calls that are close-by; derive a
  new logging context instead (e.g., if multiple logging calls refer to a
  ``"request"`` for ``"Foo"``, create a sublogger with this context by calling
  ``newLogger = parentLogger.New("request", "Foo")`` and then use
  ``newLogger.Debug("x")``).
- An empty ``log.New()`` has no impact and should be omitted.

Here is an example of how logging could be added to a type:

.. literalinclude:: /../pkg/log/wrappers_test.go
   :language: Go
   :dedent: 1
   :start-after: LITERALINCLUDE ExampleDiscardLogger START
   :end-before: LITERALINCLUDE ExampleDiscardLogger END

Metrics
-------

Metrics definition and interactions should be consistent throughout the code
base. A common pattern makes it easier for developers to implement and refactor
metrics, and for operators to understand where metrics are coming from. As a
bonus, we should leverage the type system to help us spot as many errors as
possible.

To write code that both includes metrics, and is testable, we use the metric
interfaces defined in the ``pkg/metrics/v2`` package.

A simple example with labels (note that ``Giant``'s metrics can be unit tested by
mocking the counter):

.. literalinclude:: /../pkg/metrics/v2/metrics_test.go
   :language: Go
   :dedent: 1
   :start-after: LITERALINCLUDE ExampleCounter_Implementation START
   :end-before: LITERALINCLUDE ExampleCounter_Implementation END

Calling code can later create ``Giant`` objects with Prometheus metric reporting
by plugging a prometheus counter as the ``Counter`` as shown in the example.

.. note::
   Some packages have ``metrics`` packages that define labels and initialize
   metrics (see the ``go/cs/beacon/metrics`` package for an example). While this
   is also ok, the recommended way is to define labels in the package itself and
   initialize metrics in ``main``.

Best Practices
^^^^^^^^^^^^^^

#. `prometheus.io/docs/practices/naming/ <https://prometheus.io/docs/practices/naming/>`__
#. Namespace should be one word.
#. Subsystem should be one word (if present).
#. Use values that can be searched with regex. E.g. prepend ``err_`` for every error result.
#. ``snake_case`` label names and values.
#. Put shared label names and values into ``go/lib/prom``.
#. Always initialize ``CounterVec`` to avoid hidden metrics `link <https://prometheus.io/docs/practices/instrumentation/#avoid-missing-metrics)>`_.
