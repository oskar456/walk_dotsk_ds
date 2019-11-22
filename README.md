DNSSEC-enabled delegations in .SK TLD
=====================================

This repository contains results lists of DNSSEC-secured domains in .SK TLD. You
can view raw data [in the
repository](https://github.com/oskar456/walk_dotsk_ds/tree/gh-pages) or generate
your own using [open source
implementation](https://github.com/oskar456/walk_dotsk_ds/tree/master).



<div id="chart_div"></div>
<script type="text/javascript" src="https://www.google.com/jsapi"></script>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script><!--
// Load the Visualization API and the piechart package.
    google.load('visualization', '1', {'packages':['annotationchart', 'corechart']});
// Set a callback to run when the Google Visualization API is loaded.
    google.setOnLoadCallback(drawChart);

    function drawChart() {
      $.getJSON("daystats_gchart.json", function(data) {
        var datadt = new google.visualization.DataTable(data);
        var chart = new google.visualization.ColumnChart($('#chart_div')[0]);
        var options = {
          //thickness: 6,
          height: 800,
          isStacked: true,
          explorer: { actions: ['dragToZoom', 'rightClickToReset'] },
          //colors: ['blue','red', 'grey', 'grey'],
        };
        chart.draw(datadt, options);
      });

    }
//</script>
