
function appendLoadingIndicator(element) {
    var imgPath = '/static/img/ajax-loader.gif';
    var status = element.first();
    if (!status.html().contains(imgPath)) {
        status.append('&nbsp;&nbsp;<img src="' + imgPath + '" />');
    }
}

function showLoadingIndicator(element) {
    element.first().html('');
    appendLoadingIndicator(element);
}

function initServerStatus() {
    $('td div.status-text').html('<b>...</b>');
}

function updateServerStatus() {
    $.ajax({
        url: adDetailUrl,
        dataType: "json"
    }).done(function(data) {
        var componentData = data['data'];
        if (!componentData || !componentData.length) {
            initServerStatus();
            return;
        }
        for (var i = 0; i < componentData.length; i++) {
            var info = componentData[i];
            var name = info['name'];
            var status = info['statename'];
            var $tdStatus = $('#' + name + ' .status-text');
            if ($tdStatus.html() != status) {
                $tdStatus.html(status);
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
    $('#update-topology-btn').hide();
    $('#push-update-topology-btn').hide();
}

function compareAdTopology() {
    var $alertDiv = $('#topology-info');
    var $updateTopoButton = $('#update-topology-btn');
    var $pushUpdateTopoButton = $('#push-update-topology-btn');
    $alertDiv.removeClass('alert-success alert-danger alert-warning');

    function alertNoTopology() {
        $alertDiv.addClass('alert-warning');
        $alertDiv.text('Cannot get topology');
        $updateTopoButton.hide(200);
        $pushUpdateTopoButton.hide(200);
    }

    function alertOk() {
        $alertDiv.addClass('alert-success');
        $alertDiv.text('Everything is OK');
        $updateTopoButton.hide(200);
        $pushUpdateTopoButton.hide(200);
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
        $pushUpdateTopoButton.show(200);
    }

    $.ajax({
        url: adCompareUrl,
        dataType: "json"
    }).done(function(data) {
        if (data['state'] == 'OK') {
            alertOk();
        } else if (data['state'] == 'CHANGED') {
            alertChanged(data['changes']);
        } else {
            alertNoTopology();
        }
    }).fail(function(a1, a2, a3) {
        alertNoTopology();
    }).always(function() {
        $alertDiv.hide();
        $alertDiv.show(500);
    });
    showLoadingIndicator($alertDiv);
    $alertDiv.show();
}

function showMasterServers() {
    // Remove all badges
    $('span.master-badge').remove();

    var server_types = ['bs'];
    for (var i = 0; i < server_types.length; i++) {
        var s_type = server_types[i];
        var getUrl = getMasterUrl + '?server_type=' + s_type;
        $.ajax({
            url: getUrl,
            dataType: "json"
        }).done(function(data) {
            var $serverRow = $('#' + data['server_id']);
            var $serverName = $serverRow.children().first();
            var badge = ' <span class="master-badge badge alert-success">master</span>';
            $serverName.append(badge);
        }).fail(function(a1, a2, a3) {
            // Smth happened
        });
    }
}

function makeTabsPersistent() {
    // Make tabs persistent. Check https://gist.github.com/josheinstein/5586469
    if (location.hash.substr(0,2) == "#!") {
        $("a[href='#" + location.hash.substr(2) + "']").tab("show");
    }
    var $tabLink = $("a[data-toggle='tab']");
    $tabLink.on("shown.bs.tab", function(e) {
        var hash = $(e.target).attr("href");
        if (hash.substr(0,1) == "#") {
            location.replace("#!" + hash.substr(1));
        }
    });
}

function statusControl() {
    // Process START/STOP button clicks
    $('.process-control-form > button').click(function(e) {
        var $form = $(this).parent();
        var btnName = $(this).attr('name');
        $.ajax({
            data: $form.serialize() + "&" + btnName, // form data + button
            type: $form.attr('method'),
            url: $form.attr('action'),
            dataType: 'json'
        }).always(function(response){
            updateServerStatus();
        });
        var $statusCell = $form.parent().siblings('.status-text');
        appendLoadingIndicator($statusCell);
        return false;
    });
}

function displayLogs() {
    // Callbacks for showing log dialogs

    function refreshLog(logUrl) {
        var $logOutput = $('#log-output');
        showLoadingIndicator($logOutput);
        $.ajax({
            url: logUrl,
            dataType: "json"
        }).done(function(result) {
            $logOutput.text(result['data']);
        }).fail(function(a1, a2, a3) {
            $logOutput.text('Something went wrong.')
        });
    }

    var $logWindow = $('#logModal');

    // Open log modal window
    $('.status-text').click(function() {
        var logUrl = $(this).data('log-url');
        refreshLog(logUrl);
        $logWindow.modal();
        $logWindow.data('url', logUrl);
    });

    // Refresh log button
    $('#refresh-log').click(function() {
        var logUrl = $logWindow.data('url');
        refreshLog(logUrl);
    });
}

$(document).ready(function() {
    // "Are you sure?" confirmation boxes
    $('.click-confirm').click(function(e) {
        var confirmation = $(this).data('confirmation') || 'Are you sure?';
        var res = confirm(confirmation);
        if (!res) {
            e.stopImmediatePropagation();
        }
        return res;
    });

    // Status tab callbacks
    initServerStatus();
    updateServerStatus();
    $("#update-as-btn").click(function() {
        updateServerStatus();
        showMasterServers();
    });
    // Show master labels
    showMasterServers();

    // Topology tab callbacks
    initTopologyCheck();
    compareAdTopology(adCompareUrl);
    $('#compare-topology-btn').click(function() {
        compareAdTopology(adCompareUrl);
    });

    makeTabsPersistent();

    // Update server status when the first tab is opened
    var $tabLink = $("a[data-toggle='tab']");
    $tabLink.on("shown.bs.tab", function(e) {
        if ($(e.target).attr('href') == '#servers') {
            updateServerStatus();
        }
    });

    // Status control forms
    statusControl();

    // Display log files
    displayLogs();
});
