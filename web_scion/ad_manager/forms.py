from django import forms
from django.forms import ModelChoiceField
from ad_manager.models import PackageVersion


class VersionChoiceField(ModelChoiceField):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.widget.attrs['style'] = 'height: 40px;'

    def label_from_instance(self, obj):
        assert isinstance(obj, PackageVersion)
        d = obj.date_created
        return "{} -- {}  ({:.2f} Mb)".format(obj.name, obj.date_created.date(),
                                              obj.size / 2 ** 20)


class PackageVersionSelectForm(forms.Form):

    selected_version = VersionChoiceField(
        empty_label=None,
        queryset=PackageVersion.objects.order_by('-date_created')
    )
