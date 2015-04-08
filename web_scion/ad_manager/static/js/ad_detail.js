
function initServerStatus() {
    $('td.status').html('<b>...</b>');
}

function updateServerStatus(detailUrl) {
    $.ajax({
        url: detailUrl,
        dataType: "json"
    }).done(function(data) {
        var componentData = data['data'];
        if (!componentData)
            return;
        for (var i = 0; i < componentData.length; i++) {
            var info = componentData[i];
            var name = info['name'];
            var status = info['statename'];
            var $tdStatus = $('#' + name + '> .status');
            if ($tdStatus.text() != status) {
                $tdStatus.text(status);
                $tdStatus.fadeTo(0, 0);
                $tdStatus.fadeTo(200, 1);
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
    var $updateTopoButton = $('#update-topology-btn');
    $alertDiv.hide();
    $alertDiv.removeClass('alert-success alert-danger alert-warning');

    function alertNoTopology() {
        $alertDiv.addClass('alert-warning');
        $alertDiv.text('Cannot get topology');
        $updateTopoButton.hide(200);
    }

    function alertOk() {
        $alertDiv.addClass('alert-success');
        $alertDiv.text('Everything is OK');
        $updateTopoButton.hide(200);
    }

    function alertChanged(changes) {
        $alertDiv.addClass('alert-danger');
        $alertDiv.html('Stored topology is inconsistent with the remote one<br/>');
        var $changesList = $('<ul/>').attr('id', 'changes-list');
        $.each(changes, function(index, value) {
            $('<li>' + value + '</li>').appendTo($changesList);
        });
        $alertDiv.append($changesList);
        $updateTopoButton.show(200);
    }

    $.ajax({
        url: compareUrl,
        dataType: "json"
    }).done(function(data) {
        if (data['status'] == 'OK') {
            alertOk();
        } else if (data['status'] == 'CHANGED') {
            alertChanged(data['changes']);
        } else {
            alertNoTopology();
        }
    }).fail(function(a1, a2, a3) {
        alertNoTopology();
    }).always(function() {
        $alertDiv.show(500);
    });
}

function initSendUpdates() {
    $('#update-info').hide();
}

function sendAdUpdates(sendUrl) {
    initSendUpdates();
    var $alertDiv = $('#update-info');

    function errorHandler() {
        $alertDiv.addClass('alert-warning');
        $alertDiv.text('Something is wrong');
    }

    $.ajax({
        url: sendUrl,
        dataType: "json"
    }).done(function(data) {
        if (!data['status'][0]) {
            errorHandler();
            return;
        }
        $alertDiv.addClass('alert-success');
        $alertDiv.text('Update started');
    }).fail(errorHandler
    ).always(function() {
        $alertDiv.show(500);
    });
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
    $('#compare-topology-btn').click(function() {
        compareAdTopology(adCompareUrl);
    });

    initSendUpdates();
    $('#send-updates-btn').click(function() {
        sendAdUpdates(adSendUpdatesUrl);
    });

    // "Are you sure?" confirmation boxes
    $('.click-confirm').click(function(e) {
        return confirm('Are you sure?')
    });

    // Make tabs persistent
    if (location.hash.substr(0,2) == "#!") {
        $("a[href='#" + location.hash.substr(2) + "']").tab("show");
    }
    $("a[data-toggle='tab']").on("shown.bs.tab", function (e) {
        var hash = $(e.target).attr("href");
        if (hash.substr(0,1) == "#") {
            location.replace("#!" + hash.substr(1));
        }
    });

});