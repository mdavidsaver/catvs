from distutils.core import setup
import setuptools  # noqa F401


classifiers = [
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Science/Research',
    'Programming Language :: Python',
]


setup(name='catvs',
      version='0.0.1',
      description='EPICS channel access test suite',
      packages=['catvs', 'catvs.server'],
      classifiers=classifiers,
      )
