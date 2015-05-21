from django import forms
from django.forms import ModelChoiceField
from ad_manager.models import PackageVersion, ConnectionRequest, AD


class VersionChoiceField(ModelChoiceField):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.widget.attrs['style'] = 'height: 40px;'

    def label_from_instance(self, obj):
        assert isinstance(obj, PackageVersion)
        return "{} -- {}  ({:.2f} Mb)".format(obj.name, obj.date_created.date(),
                                              obj.size / 2 ** 20)


class PackageVersionSelectForm(forms.Form):

    selected_version = VersionChoiceField(
        empty_label=None,
        queryset=PackageVersion.objects.order_by('-date_created')
    )


class ConnectionRequestForm(forms.ModelForm):

    class Meta:
        model = ConnectionRequest
        fields = ['info', 'router_ip']


class NewLinkForm(forms.Form):
    link_types = ['PARENT', 'CHILD', 'PEER', 'ROUTING']

    end_point = forms.ModelChoiceField(queryset=AD.objects.none())
    link_type = forms.ChoiceField(choices=zip(link_types, link_types))

    def __init__(self, *args, **kwargs):
        self.from_ad = kwargs.pop('from_ad')
        assert isinstance(self.from_ad, AD)
        self.base_fields['end_point'].queryset = AD.objects.exclude(id=self.from_ad.id)
        super().__init__(*args, **kwargs)
