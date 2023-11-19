from distutils.core import setup

setup(name='compactdenial',
      description='DNS Compact Denial of Existence Tools',
      author='Shumon Huque',
      author_email='shuque@gmail.com',
      url='https://github.com/shuque/compactdenial',
      py_modules=['compactdenial'],
      scripts=['compactrcode.py'],
      long_description = \
      """compactdenial - DNS compact denial of existence tools.""",
      )
