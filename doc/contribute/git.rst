.. _how-to-use-git-and-github:

*************************
How to Use Git and GitHub
*************************

If you've never used Git and/or GitHub before, GitHub assembled an `awesome list of
recommendations to get you started <https://try.github.io/>`_.

Below, you can find some additional guidelines on how to work with Git when
contributing to the SCION project. If you never used Git before, we strongly
recommend reading it.

Even if you are experienced with Git, we recommend at least skimming it because
it includes some additional information on how to write good commit messages,
and how the code review process works.

Setting up github auth
----------------------

Interacting with github using git will require you to authenticate every time.
In order to make your life easier, we strongly suggest setting up automated
authentication using an ssh-key. Github has a nice `doc on how to set it
up <https://help.github.com/articles/generating-ssh-keys/>`__.

Forking the repository
----------------------

The first step is to make your own personal fork of the main repository. You can
do this by going to the `SCION repo <https://github.com/scionproto/scion/>`__, and
clicking the 'Fork' button on the top right, and then choosing your own personal
repository.

This gives you a complete copy of the main scion repo, in which are you free to
make changes without affecting anyone else. The only downside to this is that
you have a little extra work to do to keep it up to date with the main repo.
This is covered below.

Cloning the repository
----------------------

Now that you have your own fork, follow the steps in the
:ref:`setting-up-the-development-environment` to set up
your workspace. When you get to the point of cloning the repository, use the
directory the README indicates, but clone your own fork into it instead:

.. code-block:: bash

  cd "<workspace>"
  git clone git@github.com:<username>/scion

(If you have authentication setup correctly, you won't be prompted for a password.)

This will initialize a git repository on your local machine and pull everything
from your forked personal repository in there.

Keeping your personal fork up to date
-------------------------------------

In order to keep your personal fork in sync with the main repository, you need
to add the main repo as new remote repo in your local clone. Github's `guide
for this <https://help.github.com/articles/configuring-a-remote-for-a-fork/>`__ is
pretty straightforward, but can be summarised as:

.. code-block:: bash

    git remote add upstream git@github.com:scionproto/scion.git

Now that you have this setup, the `procedure for doing the
sync <https://help.github.com/articles/syncing-a-fork/>`__ is pretty
straight-forward:

1. Fetch the changes from the main repo: ``git fetch upstream``
1. Switch to your master branch: ``git checkout master``
1. Merge the upstream changes into your main branch: ``git merge --ff-only upstream/master``
1. Push the changes to your github fork: ``git push``

A simple script to automate this can be found in the repo under
``/scripts/mastersync.sh``.

Preparing your PR
-----------------

Before you create your PR, make sure your code passes the unit testing and linting checks.

Run the tests using:

.. code-block:: bash

   ./scion.sh test

The above runs only the unit tests. As soon as you open your PR, some additional tests
will run automatically.

To lint the code, run:

.. code-block:: bash

   ./scion.sh lint

Good commit messages
--------------------

We adhere to the rules in the `Go Contribution
Guide <https://golang.org/doc/contribute.html#commit_messages>`__.

Similarly to the contribution guide above, the first commit line should complete
the sentence "This change modifies SCION to ...". This means it should start
with a lower-case letter, and should not be a complete sentence.

Do not use full URLs to reference issues, they are needlessly verbose. To
reference an issue in the current repository, use the #12345 notation. To
reference an issue in a different repository, use the Github fully-qualified
syntax (e.g., scionproto/scion#12345).

Pull Requests
-------------

Pull Requests are a powerful tool provided by github mainly to review code
before it is merged to the main branch.

In order to create a pull request you need to push your branch containing the
new code to the github repository (as explained above). This new branch will now
show up in the web interface (under 'branches' on the main repository page).
From there you can click on 'New pull request' where you can add a description
and check what's included in the pull request.

You can then assign the pull request to one or more reviewers, which will get
notified to do a code review.

Code reviews
------------

Github's code review interface is fairly basic, and is missing some key
features. To compensate for this, we're using an external review system,
[reviewable.io](reviewable.io). This integrates into the github PR, and keeps
track of comments that have been addressed or not. When all issues pointed out
by your reviewer are fixed, your code is probably ready to be merged.

Best practices
--------------

- Keep your development branch(es) rebased on master.
- Squash your contribution to a single commit before sending a PR.
- Incremental updates to a PR should be separate commits, as this allows
  reviewers to see what has changed.
- Each PR should be self-contained (as much as possible), have a description
  that covers all the changes in it, and always leave the tree in a working
  state.
- If you have any git problems, ping someone on the slack channel for help.
  Don't suffer alone :)

Final comments
--------------

Git is a very powerful tool and this tutorial barely scratches the surface. It
just presents the most common use case, but it should get you started. Please
use the vast amount of really good git and `github resources on the
web  <http://git-scm.com/book>`__.
