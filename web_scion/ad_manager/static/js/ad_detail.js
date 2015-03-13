
function initServerStatus() {
    $('td.status').html('<b>...</b>');
}

function updateServerStatus(detailUrl) {
    $.ajax({
        url: detailUrl,
        dataType: "json"
    }).done(function(data) {
        var component_data = data['data'];
        for (var i = 0; i < component_data.length; i++) {
            var info = component_data[i];
            var name = info['name'];
            var status = info['statename'];
            var $td_status = $('#' + name + '> .status');
            if ($td_status.text() != status) {
                $td_status.text(status);
                $td_status.fadeTo(0, 0);
                $td_status.fadeTo(200, 1);
            }
        }
    }).fail(function(a1, a2, a3) {
        // alert(a1 + a2 + a3);
    });
}

function initTopologyCheck() {
    $('#topology-info').hide();
}

function compareAdTopology(compareUrl) {
    var $alertDiv = $('#topology-info');
    $alertDiv.removeClass('alert-success alert-danger');

    function alert_no_topology() {
        $alertDiv.addClass('alert-warning');
        $alertDiv.text('Cannot get topology');
    }

    function alert_ok() {
        $alertDiv.addClass('alert-success');
        $alertDiv.text('OK');
    }

    function alert_changed(changes) {
        $alertDiv.addClass('alert-danger');
        $alertDiv.html('Inconsistent topology detected<br/>');
        var $changes_list = $('<ul/>').addClass('changes-list');
        $.each(changes, function(index, value) {
            $('<li>' + value + '</li>').appendTo($changes_list);
        });
        $alertDiv.append($changes_list);
    }

    $.ajax({
        url: compareUrl,
        dataType: "json"
    }).done(function(data) {
        if (data['status'] == 'OK') {
            alert_ok();
        } else if (data['status'] == 'CHANGED') {
            alert_changed(data['changes']);
        } else {
            alert_no_topology();
        }
    }).fail(function(a1, a2, a3) {
        alert_no_topology();
    });
    $alertDiv.show(500);
}

$(document).ready(function() {
    initServerStatus();
    updateServerStatus(adDetailUrl);
    $("#update-ad-btn").click(function() {
        updateServerStatus(adDetailUrl);
    });
    // setInterval(updateServerStatus, 5000); // repeat every 5 seconds


    initTopologyCheck();
    compareAdTopology(adCompareUrl);
});