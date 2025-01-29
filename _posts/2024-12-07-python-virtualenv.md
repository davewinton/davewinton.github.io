---
layout: post
title: Isolate and Manage Python Dependencies with VirtualEnv
author: Dave Winton
category: programming 
feature-img: "assets/img/pexels/computer.jpeg"
tags: [programming, python]
excerpt_separator: <!--more-->
---

If you've been writing Python code for any length of time, you've likely run into the issue of dependency management. You’re working on one project and suddenly find that a package needs to be updated, but you’re worried about breaking something in another project. Or worse yet, you find that your project is tangled with system-level packages and you can’t make a change without causing chaos.
<!--more-->

Enter `virtualenv`, your new best friend for managing dependencies in Python. 

Virtual environments allow you to create isolated environments for each of your projects, ensuring that the dependencies of one project don't interfere with another.

### Contents
- [Why Virtual Environments Are Useful:](#why-virtual-environments-are-useful)
- [Creating and Using a Virtual Environment](#creating-and-using-a-virtual-environment)
    - [Install virtualenv (if you don’t have it already):](#install-virtualenv-if-you-dont-have-it-already)
    - [Activate the Virtual Environment:](#activate-the-virtual-environment)
    - [Install Packages in the Virtual Environment:](#install-packages-in-the-virtual-environment)
- [Freeze Dependencies:](#freeze-dependencies)
- [Deactivate the Virtual Environment:](#deactivate-the-virtual-environment)
- [Recreate the Environment Elsewhere:](#recreate-the-environment-elsewhere)

## Why Virtual Environments Are Useful:

- **Isolation:** Virtual environments isolate your project's dependencies from your system and other projects. Each virtual environment can have its own versions of libraries, so you avoid version conflicts between projects. This also means you aren't directly installing the dependencies on your host machine which has security benefits.
- **Reproducibility:** With virtual environments, you can easily recreate your project’s environment on any machine. This is especially important for collaboration or when deploying to production. You can simply export the list of required packages and recreate the environment elsewhere.
- **No Permissions Issues:** Installing packages globally often requires admin privileges. Virtual environments let you install packages locally, so you avoid issues with system-wide package installations.

## Creating and Using a Virtual Environment

Here’s a quick guide to setting up and using virtual environments in Python.

#### Install virtualenv (if you don’t have it already): 

`pip install virtualenv`

Alternatively, you can use venv, which is part of Python’s standard library (available in Python 3.3+):

`python -m venv myenv`

This will create a virtual environment in a folder called `myenv`.

#### Activate the Virtual Environment:

After creating your virtual environment, you need to activate it. This will allow you to use it for the current session.

| Operating System | Command |
|------------------|---------|
| Windows          | `myenv\Scripts\activate`    |
| macOS/ Linux     | `source myenv/bin/activate` |

After activation, your prompt should change, showing the name of the environment, like this:

`(myenv) $`

#### Install Packages in the Virtual Environment:

Now that your virtual environment is active, you can install packages just like you would normally, but they’ll be installed only in this isolated environment.

`pip install requests`

This installs requests only in the virtual environment, and it won’t affect other projects or your system’s Python installation.

## Freeze Dependencies:

One of the best things about virtual environments is that you can easily save a list of your project’s dependencies. This is typically done by generating a requirements.txt file, which contains all the packages your project relies on.

`pip freeze > requirements.txt`

This will create a requirements.txt file with the exact versions of all installed packages. You can then share this file with others or use it to recreate the environment on another machine.

## Deactivate the Virtual Environment:

When you’re done working in your virtual environment, you can deactivate it with the following command:

`deactivate`

This will return you to the system’s Python environment.

## Recreate the Environment Elsewhere:

If you or a colleague want to recreate the environment elsewhere, you can do so by installing the dependencies listed in requirements.txt:

`pip install -r requirements.txt`