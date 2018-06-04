TRANSLATIONS = django_fido/locale/cs/LC_MESSAGES/django.po
TRANSLATIONS_JS = django_fido/locale/cs/LC_MESSAGES/djangojs.po

.PHONY: default msg msg-py msg-make-py msg-sort-py msg-js msg-make-js msg-sort-js

default: msg

# Translations
msg: msg-py msg-js

msg-py: msg-make-py msg-sort-py

msg-make-py:
	unset -v DJANGO_SETTINGS_MODULE; django-admin makemessages --locale cs

msg-sort-py:
	msgattrib --sort-output --no-location --no-obsolete -o ${TRANSLATIONS} ${TRANSLATIONS}

msg-js: msg-make-js msg-sort-js

msg-make-js:
	unset -v DJANGO_SETTINGS_MODULE; django-admin makemessages --locale cs --domain djangojs

msg-sort-js:
	msgattrib --sort-output --no-location --no-obsolete -o ${TRANSLATIONS_JS} ${TRANSLATIONS_JS}
