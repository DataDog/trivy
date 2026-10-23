package pipenv

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	// graph doesn't contain information about location of dependency in lock file.
	// add locations manually
	pipenvNormal = []ftypes.Package{
		{Name: "urllib3", Version: "1.24.2", Locations: []ftypes.Location{{}}},
		{Name: "requests", Version: "2.21.0", Locations: []ftypes.Location{{}}},
		{Name: "pyyaml", Version: "5.1", Locations: []ftypes.Location{{}}},
		{Name: "idna", Version: "2.8", Locations: []ftypes.Location{{}}},
		{Name: "chardet", Version: "3.0.4", Locations: []ftypes.Location{{}}},
		{Name: "certifi", Version: "2019.3.9", Locations: []ftypes.Location{{}}},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	// graph doesn't contain information about location of dependency in lock file.
	// add locations manually
	pipenvDjango = []ftypes.Package{
		{Name: "urllib3", Version: "1.24.2", Locations: []ftypes.Location{{}}},
		{Name: "sqlparse", Version: "0.3.0", Locations: []ftypes.Location{{}}},
		{Name: "requests", Version: "2.21.0", Locations: []ftypes.Location{{}}},
		{Name: "pyyaml", Version: "5.1", Locations: []ftypes.Location{{}}},
		{Name: "pytz", Version: "2019.1", Locations: []ftypes.Location{{}}},
		{Name: "idna", Version: "2.8", Locations: []ftypes.Location{{}}},
		{Name: "djangorestframework", Version: "3.9.3", Locations: []ftypes.Location{{}}},
		{Name: "django", Version: "2.2", Locations: []ftypes.Location{{}}},
		{Name: "chardet", Version: "3.0.4", Locations: []ftypes.Location{{}}},
		{Name: "certifi", Version: "2019.3.9", Locations: []ftypes.Location{{}}},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework six botocore python-dateutil simplejson setuptools pyasn1 awscli jinja2
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	// graph doesn't contain information about location of dependency in lock file.
	// add locations manually
	pipenvMany = []ftypes.Package{
		{Name: "urllib3", Version: "1.24.2", Locations: []ftypes.Location{{}}},
		{Name: "sqlparse", Version: "0.3.0", Locations: []ftypes.Location{{}}},
		{Name: "six", Version: "1.12.0", Locations: []ftypes.Location{{}}},
		{Name: "simplejson", Version: "3.16.0", Locations: []ftypes.Location{{}}},
		{Name: "s3transfer", Version: "0.2.0", Locations: []ftypes.Location{{}}},
		{Name: "rsa", Version: "3.4.2", Locations: []ftypes.Location{{}}},
		{Name: "requests", Version: "2.21.0", Locations: []ftypes.Location{{}}},
		{Name: "pyyaml", Version: "3.13", Locations: []ftypes.Location{{}}},
		{Name: "pytz", Version: "2019.1", Locations: []ftypes.Location{{}}},
		{Name: "python-dateutil", Version: "2.8.0", Locations: []ftypes.Location{{}}},
		{Name: "pyasn1", Version: "0.4.5", Locations: []ftypes.Location{{}}},
		{Name: "markupsafe", Version: "1.1.1", Locations: []ftypes.Location{{}}},
		{Name: "jmespath", Version: "0.9.4", Locations: []ftypes.Location{{}}},
		{Name: "jinja2", Version: "2.10.1", Locations: []ftypes.Location{{}}},
		{Name: "idna", Version: "2.8", Locations: []ftypes.Location{{}}},
		{Name: "framework", Version: "0.1.0", Locations: []ftypes.Location{{}}},
		{Name: "docutils", Version: "0.14", Locations: []ftypes.Location{{}}},
		{Name: "djangorestframework", Version: "3.9.3", Locations: []ftypes.Location{{}}},
		{Name: "django", Version: "2.2", Locations: []ftypes.Location{{}}},
		{Name: "colorama", Version: "0.3.9", Locations: []ftypes.Location{{}}},
		{Name: "chardet", Version: "3.0.4", Locations: []ftypes.Location{{}}},
		{Name: "certifi", Version: "2019.3.9", Locations: []ftypes.Location{{}}},
		{Name: "botocore", Version: "1.12.137", Locations: []ftypes.Location{{}}},
		{Name: "awscli", Version: "1.16.147", Locations: []ftypes.Location{{}}},
	}
)
