@set PYTHONPATH=%PYTHONPATH%;%cd%\..;%cd%\..\externals\pycrate;
pytest -s test_asn1_codec.py