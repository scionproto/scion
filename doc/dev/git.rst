*************************
How to Use Git and GitHub
*************************

Getting started
===============

If you've never used Git and/or GitHub before, GitHub assembled an `awesome list of
recommendations to get you started <https://try.github.io/>`_.

Below, you can find some additional guidelines on how to work with Git when
contributing to the SCION project. If you have never used Git before, we strongly
recommend reading it.

Even if you are experienced with Git, we recommend at least skimming it because
it includes some additional information on how to write good commit messages
and how the code review process works.

Forking the repository
----------------------

The first step is to make your own personal fork of the main repository. You can
do this by going to the `SCION repo <https://github.com/scionproto/scion/>`__, and
clicking the 'Fork' button on the top right, and then choosing your own personal
repository.

This gives you a complete copy of the main scion repo in which you are free to
make changes without affecting anyone else. The only downside is that you have a
little extra work to do to keep it up to date with the main repo.
This is covered below.

Setting up github auth
----------------------

Interacting with GitHub using Git will require you to authenticate every time.
To make your life easier, we strongly suggest setting up automated
authentication using an SSH-key. GitHub has a nice `doc on how to set it
up <https://help.github.com/articles/generating-ssh-keys/>`__.


Cloning the repository
----------------------

Now that you have your own fork, follow the steps in the
:ref:`setting-up-the-development-environment` section to set up
your workspace. When you get to the point of cloning the repository, use the
directory indicated in the README, but clone your own fork into it instead:

.. code-block:: bash

  cd "<workspace>"
  git clone git@github.com:<username>/scion

(If you have authentication setup correctly, you won't be prompted for a password.)

This will initialize a Git repository on your local machine and pull everything
from your forked personal repository.

Keeping your personal fork up to date
-------------------------------------

To keep your personal fork in sync with the main repository, you need
to add the main repo as new remote repository in your local clone. GitHub's `guide
for this <https://help.github.com/articles/configuring-a-remote-for-a-fork/>`__ is
pretty straightforward and can be summarised as follows:

.. code-block:: bash

    git remote add upstream git@github.com:scionproto/scion.git

Now that you have this setup, the `procedure for syncing <https://help.github.com/articles/syncing-a-fork/>`__ is pretty
straight-forward:

#. Fetch the changes from the main repo: ``git fetch upstream``
#. Switch to your master branch: ``git checkout master``
#. Merge the upstream changes into your main branch: ``git merge --ff-only upstream/master``
#. Push the changes to your GitHub fork: ``git push``

.. _contribute-submit-pull-request:

Submitting a pull request
=========================

Pull Requests are a powerful tool provided by GitHub mainly used to review code
before it is merged into the main branch.

Preparing your pull request
---------------------------

Before you create your pull request (PR), make sure your code passes the unit testing and linting checks.

To run the tests, use the following command:

.. code-block:: bash

   make test

The above command runs only the unit tests. As soon as you open your PR, some additional tests
will run automatically.

To lint the code, run:

.. code-block:: bash

   make lint

Good commit messages
^^^^^^^^^^^^^^^^^^^^

We adhere to the rules in the `Go Contribution
Guide <https://golang.org/doc/contribute.html#commit_messages>`__.

Here is an example of a good commit message:

.. code-block:: text

   sciond: do not panic on shutdown

   SCIOND runs a tcp-messenger in client mode. There was a superfluous
   deferred `CloseServer` call that panicked on shutdown.

   Changes:
   - Remove deferred `CloseServer` call on tcp-messenger in client mode
   - Don't panic when calling `CloseServer` on a tcp-messenger with nil listener
   - Move deferred `CloseServer` call in CS to the appropriate place

   Fixes #3766

- Starts with ``<subsystem:>``
- Uses lowercase letters for subject line
- There is always a reference number to an issue

Submitting your pull request
----------------------------

To submit a pull request, you need to push your branch containing the
new code to the GitHub repository (as explained above). This new branch will now
appear in the web interface (under 'branches' on the main repository page).
From there, you can click on 'New pull request' to add a description
and check what's included in the pull request.

You can then assign the pull request to one or more reviewers who will be
notified to perform a code review.

Code reviews
------------

GitHub's code review interface is fairly basic and lacks some key features. To compensate for this, we use an external review system,
`reviewable.io <https://reviewable.io/>`__. It integrates with the GitHub PR and keeps
track of addressed or unresolved comments. When all issues pointed out
by your reviewer are fixed, your code is likely ready to be merged.

Best practices
--------------

- Keep your development branch(es) rebased on the master branch.
- Squash your contributions into a single commit before sending a PR.
- Incremental updates to a PR should be separate commits to allow reviewers to see the change.
- Each PR should be self-contained as much as possible. It should have a description
  that covers all the changes and leave the codebase in a working
  state.
- If you encounter any Git problems, ping someone on the Slack channel for help.
  Don't struggle alone :)

Final comments
--------------

Git is a very powerful tool, and this tutorial only scratches the surface. It presents the most common use case to get you started. Please explore the vast amount of excellent Git and `github resources available on the web.
<http://git-scm.com/book>`__.
