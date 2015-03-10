
function updateServerStatus() {
    $('td.status').html('<b>...</b>');
    if (!adDetailUrl) {
        return;
    }
    $.ajax({
        url: adDetailUrl,
        dataType: "json"
    }).done(function(data) {
        component_data = data['data'];
        for (var i = 0; i < component_data.length; i++) {
            var info = component_data[i];
            var name = info['name'];
            var status = info['statename'];
            var $td_status = $('#' + name + '> .status');
            $td_status.text(status);
        }
    }).fail(function(a1, a2, a3) {
        alert(a1 + a2 + a3);
    });
}

$(document).ready(function() {
    updateServerStatus();
    $("#update-ad-btn").click(updateServerStatus);
});