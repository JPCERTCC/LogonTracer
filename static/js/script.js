function buildGraph(graph, path) {
  for (idx in path) {
    if (Object.keys(path[idx]).length == 3) {
      objid = parseInt(path[idx].identity.low) + 100;
    } else {
      objid = parseInt(path[idx].identity.low) + 1000;
    }

    // Node
    if (Object.keys(path[idx]).length == 3) {
      var ndupflg = false;
      for (nidx in graph.nodes) {
        if (graph.nodes[nidx].data.objid == objid) {
          ndupflg = true;
        }
      }
      if (ndupflg) {
        continue;
      }

      nprivilege = "";
      nsub = "";
      ncategory = "";
      if (path[idx].labels[0] == "Username") {
        nname = path[idx].properties.user
        nfsize = "10"
        nshape = "ellipse"
        nwidth = "25"
        nheight = "25"
        ntype = "User"
        if (path[idx].properties.rights == "system") {
          ncolor = "#ff0000"
          nbcolor = "#ffc0cb"
          nfcolor = "#ff69b4"
          nprivilege = "SYSTEM"
        } else {
          ncolor = "#0000cd"
          nbcolor = "#cee1ff"
          nfcolor = "#6da0f2"
          nprivilege = "Normal"
        }
        if (path[idx].properties.status != "-") {
          ncolor = "#404040"
          nshape = "octagon"
        }
      }
      if (path[idx].labels[0] == "IPAddress") {
        nname = path[idx].properties.IP
        nshape = "diamond"
        nwidth = "25"
        nheight = "25"
        nfsize = "8"
        ncolor = "#2e8b57"
        nbcolor = "#98fb98"
        nfcolor = "#3cb371"
        ntype = "Host"
      }
      if (path[idx].labels[0] == "Domain") {
        nname = path[idx].properties.domain
        nshape = "rectangle"
        nwidth = "25"
        nheight = "25"
        nfsize = "10"
        ncolor = "#8b2e86"
        nbcolor = "#fa98ef"
        nfcolor = "#b23aa2"
        ntype = "Domain"
      }
      if (path[idx].labels[0] == "ID") {
        nname = path[idx].properties.changetime
        nuser = path[idx].properties.user
        nsub = path[idx].properties.sub
        ncategory = path[idx].properties.category
        nshape = "hexagon"
        nwidth = "25"
        nheight = "25"
        nfsize = "10"
        ncolor = "#8b6f2e"
        nbcolor = "#f9d897"
        nfcolor = "#b28539"
        ntype = "Policy"
      }
      graph.nodes.push({
        "data": {
          "id": objid,
          "objid": objid,
          "nlabel": nname,
          "ncolor": ncolor,
          "nbcolor": nbcolor,
          "nfcolor": nfcolor,
          "nwidth": nwidth,
          "nheight": nheight,
          "nfsize": nfsize,
          "nshape": nshape,
          "label": path[idx].labels[0],
          "nprivilege": nprivilege,
          "ntype": ntype,
          "nsid": path[idx].properties.sid,
          "nstatus": path[idx].properties.status,
          "nhostname": path[idx].properties.hostname,
          "nsub": nsub,
          "ncategory": ncategory
        }
      });
    } else {
      // Relationship
      var ldupflg = false;
      for (nidx in graph.edges) {
        if (graph.edges[nidx].data.objid == objid) {
          ldupflg = true;
        }
      }
      if (ldupflg) {
        continue;
      }
      if (path[idx].type == "Event") {
        var label_count = document.getElementById("label-count").checked;
        var label_type = document.getElementById("label-type").checked;
        var label_status = document.getElementById("label-status").checked;
        var label_authname = document.getElementById("label-authname").checked;
        var ename = path[idx].properties.id;
        if (label_count) {
          ename += " : " + path[idx].properties.count;
        }
        if (label_type) {
          ename += " : " + path[idx].properties.logintype;
        }
        if (label_status) {
          ename += " : " + path[idx].properties.status;
        }
        if (label_authname) {
          ename += " : " + path[idx].properties.authname;
        }
        graph.edges.push({
          "data": {
            "id": objid,
            "source": parseInt(path[parseInt(idx) - 1].identity.low) + 100,
            "target": parseInt(path[parseInt(idx) + 1].identity.low) + 100,
            "objid": objid,
            "elabel": ename,
            "label": path[idx].type,
            "distance": 5,
            "ntype": "edge",
            "eid": path[idx].properties.id,
            "count": path[idx].properties.count,
            "logontype": path[idx].properties.logintype,
            "status": path[idx].properties.status,
            "authname": path[idx].properties.authname
          }
        });
      } else {
        graph.edges.push({
          "data": {
            "id": objid,
            "source": parseInt(path[parseInt(idx) - 1].identity.low) + 100,
            "target": parseInt(path[parseInt(idx) + 1].identity.low) + 100,
            "objid": objid,
            "label": path[idx].type,
            "distance": 5,
            "ntype": "edge",
          }
        });
      }
    }
  }

  return (graph);
}

function drawGraph(graph, rootNode) {
  var flagGrid = document.getElementById("modeGrid").checked;
  var flagCose = document.getElementById("modeCose").checked;
  var flagCircle = document.getElementById("modeCircle").checked;
  var flagMode = "";

  if (flagGrid) {
    flagMode = "grid";
  }
  if (flagCose) {
    flagMode = "cose";
  }
  if (flagCircle) {
    flagMode = "circle";
  }

  cy = cytoscape({
    container: document.getElementById("cy"),
    boxSelectionEnabled: false,
    style: cytoscape.stylesheet()
      .selector('node').css({
        "content": "data(nlabel)",
        "width": "data(nwidth)",
        "height": "data(nheight)",
        "color": "data(ncolor)",
        "font-size": "data(nfsize)",
        "background-color": "data(nbcolor)",
        "border-color": "data(nfcolor)",
        "border-style": "solid",
        "border-width": 3,
        "text-valign": "center",
        "text-outline-width": 1,
        "text-outline-color": "data(nbcolor)",
        "shape": "data(nshape)"
      })
      .selector(':selected').css({
        "width": 25,
        "height": 25,
        "border-width": 4,
        "border-color": "#404040"
      })
      .selector('edge').css({
        "content": "data(elabel)",
        "font-size": "8",
        "curve-style": "bezier",
        "target-arrow-shape": "triangle",
        "width": 2,
        "line-color": "#ddd",
        "target-arrow-color": "#ddd"
      })
      .selector('.highlighted').css({
        "background-color": "#61bffc",
        "line-color": "#61bfcc",
        "transition-property": "background-color, line-color, target-arrow-color",
        "transition-duration": "0.5s"
      }),
    elements: graph,
    layout: {
      name: flagMode,
      directed: true,
      roots: rootNode,
      animate: true,
      padding: 10
    }
  });

  cy.on("layoutstop", function() {
    loading.classList.add("loaded");
  });

  cy.nodes().forEach(function(ele) {
    ele.qtip({
      content: {
        title: "<b>Node Details</b>",
        text: qtipNode(ele)
      },
      style: {
        classes: "qtip-bootstrap"
      },
      position: {
        my: "top center",
        at: "bottom center",
        target: ele
      }
    });
  });

  cy.edges().forEach(function(ele) {
    ele.qtip({
      content: {
        title: "<b>Details</b>",
        text: qtipEdge(ele)
      },
      style: {
        classes: "qtip-bootstrap"
      },
      position: {
        my: "top center",
        at: "bottom center",
        target: ele
      }
    });
  });
}

function qtipNode(ndata) {
  var qtext = 'Name: ' + ndata._private.data["nlabel"];
  if (ndata._private.data["ntype"] == "User") {
    qtext += '<br>Privilege: ' + ndata._private.data["nprivilege"];
    qtext += '<br>SID: ' + ndata._private.data["nsid"];
    qtext += '<br>Status: ' + ndata._private.data["nstatus"];
  } else if (ndata._private.data["ntype"] == "Host") {
    qtext += '<br>Hostname: ' + ndata._private.data["nhostname"];
  } else if (ndata._private.data["ntype"] == "Policy") {
    qtext = "";
    qtext += 'Date: ' + ndata._private.data["nlabel"];
    qtext += '<br>Category: ' + ndata._private.data["ncategory"];
    qtext += '<br>Subcategory: ' + ndata._private.data["nsub"];
  }

  if (ndata._private.data["ntype"] != "Policy") {
    qtext += '<br><button type="button" class="btn btn-primary btn-xs" onclick="createRankQuery(\'' + ndata._private.data["nlabel"] + '\',\'' + ndata._private.data["ntype"] + '\')">search</button>';
  }

  return qtext;
}

function qtipEdge(ndata) {
  var qtext = "";
  if (ndata._private.data["label"] == "Event") {
    if (ndata._private.data["eid"] == 4624) {
      qtext = "<b>Successful logon</b><br>";
    }
    if (ndata._private.data["eid"] == 4625) {
      qtext = "<b>Logon failure</b><br>";
    }
    if (ndata._private.data["eid"] == 4768) {
      qtext = "<b>Kerberos Authentication (TGT Request)</b><br>";
    }
    if (ndata._private.data["eid"] == 4769) {
      qtext = "<b>Kerberos Service Ticket (ST Request)</b><br>";
    }
    if (ndata._private.data["eid"] == 4776) {
      qtext = "<b>NTLM Authentication</b><br>";
    }
    qtext += "Count: " + ndata._private.data["count"];
    qtext += "<br>Logon Type: " + ndata._private.data["logontype"];
    qtext += "<br>AuthName: " + ndata._private.data["authname"];
    qtext += "<br>Status: " + ndata._private.data["status"];
  } else if (ndata._private.data["label"] == "Group") {
    qtext = "Domain group";
  } else {
    qtext = "Audit policy change";
  }
  return qtext;
}

function createAllQuery() {
  eidStr = getQueryID();
  eidStr = eidStr.slice(4);
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE ' + eidStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createSystemQuery() {
  eidStr = getQueryID();
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE user.rights = "system" ' + eidStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createRDPQuery() {
  eidStr = getQueryID();
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 10 ' + eidStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createNetQuery() {
  eidStr = getQueryID();
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 3 ' + eidStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createBatchQuery() {
  eidStr = getQueryID();
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 4 ' + eidStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createServiceQuery() {
  eidStr = getQueryID();
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 5 ' + eidStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function create14068Query() {
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.status = "0xf" AND event.id = 4769 RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createFailQuery() {
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.id = 4625 RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createNTLMQuery() {
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.id = 4624 and event.authname = "NTLM" and event.logintype = 3 RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function adddelUsersQuery() {
  queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE NOT (user.status = "-") RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createDomainQuery() {
  queryStr = 'MATCH (user)-[event:Group]-(ip) RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function policyQuery() {
  queryStr = 'MATCH (user)-[event:Policy]-(ip) RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function createRankQuery(setStr, qType) {
  if (qType == "User") {
    whereStr = 'user.user = "' + setStr + '" ';
  }
  if (qType == "Host") {
    whereStr = 'ip.IP = "' + setStr + '" ';
  }

  if (qType != "Domain") {
    eidStr = getQueryID();
    queryStr = 'MATCH (user)-[event:Event]-(ip)  WHERE (' + whereStr + ') ' + eidStr + ' RETURN user, event, ip';
  } else {
    queryStr = 'MATCH (user)-[event:Group]-(ip) WHERE user.domain = "' + setStr + '" RETURN user, event, ip'
  }
  //console.log(queryStr);
  executeQuery(queryStr);
}

function getQueryID() {
  var id4624Ch = document.getElementById("id4624").checked;
  var id4625Ch = document.getElementById("id4625").checked;
  var id4768Ch = document.getElementById("id4768").checked;
  var id4769Ch = document.getElementById("id4769").checked;
  var id4776Ch = document.getElementById("id4776").checked;
  var countInt = document.getElementById("count-input").value;
  var eidStr = "AND ("
  if (id4624Ch) {
    eidStr = eidStr + "event.id = 4624 OR ";
  }
  if (id4625Ch) {
    eidStr = eidStr + "event.id = 4625 OR ";
  }
  if (id4768Ch) {
    eidStr = eidStr + "event.id = 4768 OR ";
  }
  if (id4769Ch) {
    eidStr = eidStr + "event.id = 4769 OR ";
  }
  if (id4776Ch) {
    eidStr = eidStr + "event.id = 4776 OR ";
  }
  eidStr = eidStr.slice(0, -4) + ")";
  eidStr = eidStr + " AND event.count > " + countInt;

  return eidStr;
}

function createQuery() {
  var selectVal = document.getElementById("InputSelect").value;
  var setStr = document.getElementById("query-input").value;

  if (selectVal == "Username") {
    whereStr = 'user.user =~ "' + setStr + '" ';
  } else if (selectVal == "IPAddress") {
    whereStr = 'ip.IP =~ "' + setStr + '" ';
  } else {
    whereStr = 'ip.hostname =~ "' + setStr + '" ';
  }

  for (i = 1; i <= currentNumber; i++) {
    if (document.getElementById("query-input" + i).value) {
      ruleStr = document.getElementById("InputRule" + i).value;
      if (document.getElementById("InputSelect" + i).value == "Username") {
        whereStr += ruleStr + ' user.user =~ "' + document.getElementById("query-input" + i).value + '" ';
      } else if (document.getElementById("InputSelect" + i).value == "IPAddress") {
        whereStr += ruleStr + ' ip.IP =~ "' + document.getElementById("query-input" + i).value + '" ';
      } else {
        whereStr += ruleStr + ' ip.hostname =~ "' + document.getElementById("query-input" + i).value + '" ';
      }
    }
  }

  eidStr = getQueryID()
  queryStr = 'MATCH (user)-[event:Event]-(ip)  WHERE (' + whereStr + ') ' + eidStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr);
}

function sendQuery(queryStr) {
  var graph = {
    "nodes": [],
    "edges": []
  };

  var loading = document.getElementById('loading');
  loading.classList.remove('loaded');

  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        //console.log(record.get('user'), record.get('event'), record.get('ip'));
        graph = buildGraph(graph, [record.get("user"), record.get("event"), record.get("ip")]);
      },
      onCompleted: function() {
        session.close();
        if (graph.nodes.length == 0) {
          searchError();
          loading.classList.add("loaded");
        } else {
          //console.log(graph);
          rootNode = graph.nodes[0].id;
          drawGraph(graph, rootNode);
        }
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

function executeQuery(queryStr) {
  var countStr = queryStr.replace("user, event, ip" , "COUNT(event)");

  session.run(countStr)
    .subscribe({
      onNext: function(record) {
        recordCount = record._fields[0].low;
      },
      onCompleted: function() {
        session.close();
        if (recordCount > 3000) {
          setqueryStr = queryStr;
          $('#warningMessage').modal({
            show: true,
            backdrop: 'false'
          });
        } else {
          sendQuery(queryStr);
        }
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

var setqueryStr = "";
function contQuery() {
  sendQuery(setqueryStr);
}

function pruserBack() {
  rankpageUser -= 1;
  if (rankpageUser < 0) {
    rankpageUser = 0;
  }
  pagerankQuery(userqueryStr, "User", rankpageUser);
}

function pruserNext() {
  rankpageUser += 1;
  if (rankpageUser < 0) {
    rankpageUser = 0;
  }
  pagerankQuery(userqueryStr, "User", rankpageUser);
}

function prhostBack() {
  rankpageHost -= 1;
  if (rankpageHost < 0) {
    rankpageHost = 0;
  }
  pagerankQuery(ipqueryStr, "Host", rankpageHost);
}

function prhostNext() {
  rankpageHost += 1;
  if (rankpageHost < 0) {
    rankpageHost = 0;
  }
  pagerankQuery(ipqueryStr, "Host", rankpageHost);
}

function pagerankQuery(queryStr, dataType, currentPage) {
  var nodes = new Array();
  var html = '<div><table class="table table-striped"><thead><tr class="col-sm-2 col-md-2">\
              <th class="col-sm-1 col-md-1">Rank</th><th class="col-sm-1 col-md-1">' + dataType +
    '</th></tr></thead><tbody class="col-sm-2 col-md-2">';
  var startRunk = currentPage * 10;
  queryStr = queryStr + " SKIP " + startRunk + " LIMIT " + 10;
  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        nodeData = record.get("node");
        if (dataType == "User") {
          nodes.push([nodeData.properties.user, nodeData.properties.rank]);
        }
        if (dataType == "Host") {
          nodes.push([nodeData.properties.IP, nodeData.properties.rank]);
        }
      },
      onCompleted: function() {
        session.close();
        for (i = 0; i < nodes.length; i++) {
          html += '<tr><td>' + (currentPage * 10 + i + 1) + '</td><td><a onclick="createRankQuery(\'' + nodes[i][0] + '\', \'' + dataType + '\')">' + nodes[i][0] + '</a></td></tr>';
          //console.log(nodes[i][0]);
          //console.log(hosts[i][0]);
        }
        html += '</tbody></table></div>';

        if (dataType == "User") {
          var rankElem = document.getElementById("rankUser");
        }
        if (dataType == "Host") {
          var rankElem = document.getElementById("rankHost");
        }
        rankElem.innerHTML = html;
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

function exportCSV() {
  var queryStr = 'MATCH (user:Username)-[event:Event]-(ip:IPAddress) RETURN user, ip, event';
  var events = new Array();

  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        eventData = record.get("event");
        userData = record.get("user");
        ipData = record.get("ip");
        events.push([userData.properties.user, ipData.properties.IP,
          eventData.properties.id, eventData.properties.logintype,
          eventData.properties.status, eventData.properties.count,
          eventData.properties.authname
        ]);
      },
      onCompleted: function() {
        session.close();
        var rowData = "username,host,id,logontype,status,count,authname\r\n";
        for (i = 0; i < events.length; i++) {
          rowData += events[i][0] + ",";
          rowData += events[i][1] + ",";
          rowData += events[i][2] + ",";
          rowData += events[i][3] + ",";
          rowData += events[i][4] + ",";
          rowData += events[i][5] + ",";
          rowData += events[i][6] + "\r\n";
        }
        var downLoadLink = document.createElement("a");
        downLoadLink.download = "image.csv";
        downLoadLink.href = URL.createObjectURL(new Blob([rowData], {
          type: "application.csv"
        }));
        downLoadLink.dataset.downloadurl = ["application/csv", downLoadLink.download, downLoadLink.href].join(":");
        downLoadLink.click();
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

function exportJSON() {
  var jsonData = "data:application/json,";
  jsonData += encodeURIComponent(JSON.stringify(cy.json()));
  var exptag = document.getElementById('export-json');
  exptag.href = jsonData;
}

function exportPNG() {
  var png64 = cy.png();
  var exptag = document.getElementById('export-png');
  exptag.href = png64;
}

function exportJPEG() {
  var jpg64 = cy.png();
  var exptag = document.getElementById('export-jpeg');
  exptag.href = jpg64;
}

function downloadCSV(csvType) {
  var queryStr = 'MATCH (date:Date) MATCH (user:Username) RETURN date, user';
  var users = new Array();

  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        nodeData = record.get("user");
        dateData = record.get("date");
        users.push([nodeData.properties.user, nodeData.properties.counts,
          nodeData.properties.counts4624, nodeData.properties.counts4625,
          nodeData.properties.counts4768, nodeData.properties.counts4769,
          nodeData.properties.counts4776
        ]);
        starttime = dateData.properties.start;
        endtime = dateData.properties.end;
      },
      onCompleted: function() {
        session.close();

        var startDate = new Date(starttime);
        var rangeHours = Math.floor((Date.parse(endtime) - Date.parse(starttime)) / (1000 * 60 * 60)) + 1;
        var rawDate = "username,";
        if (csvType == "detail") {
          rawDate += "id,";
        }
        var countData = "";
        for (i = 0; i < rangeHours; i++) {
          rawDate += startDate.toISOString() + ",";
          startDate.setHours(startDate.getHours() + 1);
        }

        if (csvType == "summary") {
          for (i = 0; i < users.length; i++) {
            countData += users[i][0] + "," + users[i][1] + "\r\n";
          }
        } else if (csvType == "detail") {
          for (i = 0; i < users.length; i++) {
            countData += users[i][0];
            for (j = 2; j <= 6; j++) {
              if (j == 2) {
                countData += ",4624,";
              } else if (j == 3) {
                countData += ",4625,";
              } else if (j == 4) {
                countData += ",4768,";
              } else if (j == 5) {
                countData += ",4769,";
              } else if (j == 6) {
                countData += ",4776,";
              }
              countData += users[i][j] + "\r\n";
            }
          }
        }

        rawDate += "\r\n" + countData
        var downLoadLink = document.createElement("a");
        downLoadLink.download = "timeline.csv";
        downLoadLink.href = URL.createObjectURL(new Blob([rawDate], {
          type: "application.csv"
        }));
        downLoadLink.dataset.downloadurl = ["application/csv", downLoadLink.download, downLoadLink.href].join(":");
        downLoadLink.click();
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

function downloadSummary() {
  downloadCSV("summary");
}

function downloadDetail() {
  downloadCSV("detail");
}

function createTimeline(queryStr, tableType) {
  var users = new Array();
  var starttime = "";
  var endtime = "";
  var weekTbl = new Array("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");
  var bgcolorTbl = new Array("#ff7f50", "#efefef", "#efefef", "#efefef", "#efefef", "#efefef", "#b0c4de");

  if (tableType == "all") {
    var span = 'rowspan = "4"';
  }
  if (tableType == "search") {
    var span = 'rowspan = "4" colspan="2"';
  }
  var html = '<div class="table-responsive"><table class="table table-bordered table-condensed table-striped table-wrapper" style="background-color:#EEE;"><thead><tr>\
                    <th ' + span + '>Username</th>';

  for (i = 0; i < chartArray.length; i ++) {
    if (chartArray[i]) {
      chartArray[i].destroy();
    }
  }

  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        dateData = record.get("date");
        nodeData = record.get("user");
        users.push([nodeData.properties.user, nodeData.properties.counts, nodeData.properties.detect, nodeData.properties.rights, nodeData.properties.counts4624,
          nodeData.properties.counts4625, nodeData.properties.counts4768, nodeData.properties.counts4769, nodeData.properties.counts4776
        ]);
        starttime = dateData.properties.start;
        endtime = dateData.properties.end;
      },
      onCompleted: function() {
        session.close();
        var startDate = new Date(starttime);
        var rangeHours = Math.floor((Date.parse(endtime) - Date.parse(starttime)) / (1000 * 60 * 60)) + 1;
        var thisyear = startDate.getFullYear();
        var thismonth = startDate.getMonth();
        var thisday = startDate.getDate();
        var thishour = startDate.getHours();
        var thisdow = startDate.getDay();
        var nextyear = null;
        var nrangeHours = 0;
        var weekd = 0;
        for (i = 1; i <= rangeHours; i++) {
          startDate.setHours(startDate.getHours() + 1);
          if (startDate.getFullYear() != thisyear) {
            html += '<th colspan="' + (i - nrangeHours) + '">' + thisyear + '</th>';
            thisyear = startDate.getFullYear();
            nrangeHours = i;
          }
        }
        html += '<th colspan="' + (rangeHours - nrangeHours) + '">' + thisyear + '</th></tr><tr>';

        nrangeHours = 0;
        startDate = new Date(starttime);
        for (i = 1; i <= rangeHours; i++) {
          startDate.setHours(startDate.getHours() + 1);
          if (startDate.getMonth() != thismonth) {
            html += '<th colspan="' + (i - nrangeHours) + '">' + (thismonth + 1) + '</th>';
            thismonth = startDate.getMonth();
            nrangeHours = i;
          }
        }
        html += '<th colspan="' + (rangeHours - nrangeHours) + '">' + (thismonth + 1) + '</th></tr><tr>';

        nrangeHours = 0;
        startDate = new Date(starttime);
        for (i = 1; i <= rangeHours; i++) {
          startDate.setHours(startDate.getHours() + 1);
          if (startDate.getDate() != thisday) {
            html += '<th bgcolor="' + bgcolorTbl[thisdow + weekd] + '" colspan="' + (i - nrangeHours) + '">' + thisday + '(' + weekTbl[thisdow + weekd] + ')</th>';
            if (thisdow + weekd >= 6) {
              thisdow = 0 - (weekd + 1);
            }
            thisday = startDate.getDate();
            nrangeHours = i;
            weekd += 1;
          }
        }
        html += '<th bgcolor="' + bgcolorTbl[thisdow + weekd] + '" colspan="' + (rangeHours - nrangeHours) + '">' + thisday + '(' + weekTbl[thisdow + weekd] + ')</th></tr><tr>';

        for (i = 0; i < rangeHours; i++) {
          html += '<th>' + thishour + '</th>';
          thishour += 1;
          if (thishour >= 24) {
            thishour = 0;
          }
        }

        html += '</tr></thead><tbody>';

        if (tableType == "all") {
          for (i = 0; i < users.length; i++) {
            if (users[i][3] == "system") {
              html += '<tr><td><a onclick="clickTimeline(\'' + users[i][0] + '\')"><font color="#ff7f50">' + users[i][0] + '</font></a></td>';
            } else {
              html += '<tr><td><a onclick="clickTimeline(\'' + users[i][0] + '\')">' + users[i][0] + '</a></td>';
            }
            rowdata = users[i][1].split(",");
            alerts = users[i][2].split(",");
            for (j = 0; j < rowdata.length; j++) {
              if (alerts[j] > 17) {
                html += '<td bgcolor="#ff5aee">' + rowdata[j].split(".")[0] + '</td>';
              } else if (alerts[j] > 16) {
                html += '<td bgcolor="#ff8aee">' + rowdata[j].split(".")[0] + '</td>';
              } else if (alerts[j] > 13) {
                html += '<td bgcolor="#ffbaee">' + rowdata[j].split(".")[0] + '</td>';
              } else if (alerts[j] > 10) {
                html += '<td bgcolor="#ffeaee">' + rowdata[j].split(".")[0] + '</td>';
              } else {
                html += '<td>' + rowdata[j].split(".")[0] + '</td>';
              }
            }
            html += '</tr>';
          }
        }

        if (tableType == "search") {
          for (i = 0; i < users.length; i++) {
            if (users[i][3] == "system") {
              html += '<tr><td rowspan = "5"><a onclick="clickTimeline(\'' + users[i][0] + '\')"><font color="#ff7f50">' + users[i][0] + '</font></a></td>';
            } else {
              html += '<tr><td rowspan = "5"><a onclick="clickTimeline(\'' + users[i][0] + '\')">' + users[i][0] + '</a></td>';
            }

            for (j = 4; j <= 8; j++) {
              rowdata = users[i][j].split(",");
              alerts = users[i][2].split(",");
              if (j == 4) {
                html += '<td>4624</td>';
              } else if (j == 5) {
                html += '<td>4625</td>';
              } else if (j == 6) {
                html += '<td>4768</td>';
              } else if (j == 7) {
                html += '<td>4769</td>';
              } else if (j == 8) {
                html += '<td>4776</td>';
              }
              for (k = 0; k < rowdata.length; k++) {
                if (alerts[k] > 17) {
                  html += '<td bgcolor="#ff5aee">' + rowdata[k].split(".")[0] + '</td>';
                } else if (alerts[k] > 16) {
                  html += '<td bgcolor="#ff8aee">' + rowdata[k].split(".")[0] + '</td>';
                } else if (alerts[k] > 13) {
                  html += '<td bgcolor="#ffbaee">' + rowdata[k].split(".")[0] + '</td>';
                } else if (alerts[k] > 10) {
                  html += '<td bgcolor="#ffeaee">' + rowdata[k].split(".")[0] + '</td>';
                } else {
                  html += '<td>' + rowdata[k].split(".")[0] + '</td>';
                }
              }
              html += '</tr>';
            }
          }
        }
        html += '</tbody></table></div>';

        var timelineElem = document.getElementById("cy");
        timelineElem.innerHTML = html;

        $(function(){
          $(".table.table-wrapper").floatThead({
            responsiveContainer: function($table){
              return $table.closest(".table-responsive");
            }
          });
        });
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

var chartArray = new Array();
function createTimelineGraph(queryStr) {
  var users = new Array();
  var dates = new Array();
  var starttime = "";
  var endtime = "";

  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        dateData = record.get("date");
        nodeData = record.get("user");
        users.push([nodeData.properties.user, nodeData.properties.counts4624, nodeData.properties.counts4625, nodeData.properties.counts4768,
                    nodeData.properties.counts4769, nodeData.properties.counts4776, nodeData.properties.detect]);
        starttime = dateData.properties.start;
        endtime = dateData.properties.end;
      },
      onCompleted: function() {
        session.close();
        var canvasArray = addCanvas(users);
        var startDate = new Date(starttime);
        var rangeHours = Math.floor((Date.parse(endtime) - Date.parse(starttime)) / (1000 * 60 * 60)) + 1;
        for (i = 1; i <= rangeHours; i++) {
          startDate.setHours(startDate.getHours() + 1);
          dates.push(formatDate(startDate))
        }

        for (i = 0; i < users.length; i++) {
          var ctx = canvasArray[i].getContext("2d");
          chartArray[i] = new Chart(ctx, {
            type: "line",
            data: {
              labels: dates,
              datasets: [
              {
                label: "4624",
                borderColor: "rgb(141, 147, 200)",
                backgroundColor: "rgb(141, 147, 200)",
                pointHoverBorderColor: "rgb(255, 0, 0)",
                lineTension: 0,
                fill: false,
                data: users[i][1].split(","),
                pointRadius: 5,
                pointHoverRadius: 10,
              },
              {
                label: "4625",
                borderColor: "rgb(89, 195, 225)",
                backgroundColor: "rgb(89, 195, 225)",
                pointHoverBorderColor: "rgb(255, 0, 0)",
                lineTension: 0,
                fill: false,
                data: users[i][2].split(","),
                pointRadius: 5,
                pointHoverRadius: 10,
              },
              {
                label: "4768",
                borderColor: "rgb(30, 44, 92)",
                backgroundColor: "rgb(30, 44, 92)",
                pointHoverBorderColor: "rgb(255, 0, 0)",
                lineTension: 0,
                fill: false,
                data: users[i][3].split(","),
                pointRadius: 5,
                pointHoverRadius: 10,
              },
              {
                label: "4769",
                borderColor: "rgb(1, 96, 140)",
                backgroundColor: "rgb(1, 96, 140)",
                pointHoverBorderColor: "rgb(255, 0, 0)",
                lineTension: 0,
                fill: false,
                data: users[i][4].split(","),
                pointRadius: 5,
                pointHoverRadius: 10,
              },
              {
                label: "4776",
                borderColor: "rgb(0, 158, 150)",
                backgroundColor: "rgb(0, 158, 150)",
                pointHoverBorderColor: "rgb(255, 0, 0)",
                lineTension: 0,
                fill: false,
                data: users[i][5].split(","),
                pointRadius: 5,
                pointHoverRadius: 10,
              },
              {
                label: "Anomaly Score",
                borderColor: "rgb(230, 0, 57)",
                backgroundColor: "rgb(230, 0, 57)",
                pointHoverBorderColor: "rgb(255, 0, 0)",
                lineTension: 0,
                fill: false,
                data: users[i][6].split(","),
                pointRadius: 5,
                pointHoverRadius: 10,
                yAxisID: "y-right",
              },
              ]
            },
            options: {
              responsive: true,
              legend: {
      					position: "bottom",
                fontSize: 15,
      				},
      				scales: {
      					xAxes: [{
      						display: true,
      						scaleLabel: {
      							display: true,
                    fontSize: 15,
      							labelString: "Date"
      						}
      					}],
      					yAxes: [{
      						display: true,
      						scaleLabel: {
      							display: true,
                    fontSize: 15,
      							labelString: "Count"
      						}
      					},
                {
      						display: true,
                  id: "y-right",
                  position: "right",
      						scaleLabel: {
      							display: true,
                    fontSize: 15,
      							labelString: "Score"
      						},
                  ticks: {
                    max: 20
                  }
      					}]
      				},
              title: {
                  display: true,
                  fontSize: 18,
                  text: users[i][0]
              },
              elements: {
  						  point: {
  							  pointStyle: "crossRot"
  					  	}
  					  }
            }
          });
        }

        var timelineElem = document.getElementById("cy");
        timelineElem.innerHTML = "";
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

function addCanvas(users){
    var canvasArray = new Array();
    var obj = document.getElementById("addcanvas");
    obj.textContent = null;

    for (i = 1; i <= users.length; i++) {
      var canvas = document.createElement("canvas");
      canvas.id = "canvas" + i;
      canvas.style = "height:400px;";
      canvasArray.push(canvas);

      obj.appendChild(canvas);
    }

    return canvasArray;
}

function createAlltimeline() {
  var queryStr = 'MATCH (date:Date) MATCH (user:Username) RETURN date, user';
  createTimeline(queryStr, "all");
}

function searchTimeline() {
  var selectVal = document.getElementById("InputSelect").value;
  var setStr = document.getElementById("query-input").value;

  if (selectVal == "Username") {
    whereStr = 'user.user =~ "' + setStr + '" ';
  } else {
    searchError();
  }

  for (i = 1; i <= currentNumber; i++) {
    if (document.getElementById("query-input" + i).value) {
      if (document.getElementById("InputSelect" + i).value == "Username") {
        whereStr += 'or user.user =~ "' + document.getElementById("query-input" + i).value + '" ';
      } else {
        searchError();
      }
    }
  }
  var queryStr = 'MATCH (date:Date) MATCH (user:Username) WHERE (' + whereStr + ') RETURN date, user';
  var gtype = document.getElementById("timelineTypes").checked;
  if (gtype) {
    createTimeline(queryStr, "search");
  } else {
    createTimelineGraph(queryStr);
  }
}

function clickTimeline(setStr) {
  whereStr = 'user.user =~ "' + setStr + '" ';

  var queryStr = 'MATCH (date:Date) MATCH (user:Username) WHERE (' + whereStr + ') RETURN date, user';
  var gtype = document.getElementById("timelineTypes").checked;
  if (gtype) {
    createTimeline(queryStr, "search");
  } else {
    createTimelineGraph(queryStr);
  }
}


function logdeleteCheck() {
  var queryStr = "MATCH (date:Deletetime) RETURN date";
  var ddata = "";

  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        ddata = record.get("date");
      },
      onCompleted: function() {
        session.close();
        if (ddata.length != 0) {
          delDate = ddata.properties.date;
          delDomain = ddata.properties.domain;
          delUser = ddata.properties.user;

          var elemMsg = document.getElementById("error");
          elemMsg.innerHTML =
            '<div class="alert alert-danger alert-dismissible" id="alertfadeout" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="close">\
            <span aria-hidden="true">×</span></button><strong>IMPORTANT</strong>: Delete Event Log has detected! If you have not deleted the event log, the attacker may have deleted it.\
            <br>DATE: ' + delDate + '  DOMAIN: ' + delDomain + '  USERNAME: ' + delUser + '</div>';
        }
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

function searchError() {
  var elemMsg = document.getElementById("error");
  elemMsg.innerHTML =
    '<div class="alert alert-warning alert-dismissible" id="alertfadeout" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="close">\
    <span aria-hidden="true">×</span></button><strong>WARNING</strong>: Search failed!</div>';
  $(document).ready(function() {
    $('#alertfadeout').fadeIn(2000).delay(4000).fadeOut(2000);
  });
}

function file_upload() {
  var upfile = document.getElementById("lefile");
  var timezone = document.getElementById("utcTime").value;
  var logtype = document.getElementById("logType").value;

  if (timezone == "Time Zone") {
    document.getElementById("status").innerHTML = '<div class="alert alert-danger"><strong>ERROR</strong>: Please set the time zone of the event logs.</div>';
  } else {
    document.getElementById("uploadBar").innerHTML = '';
    document.getElementById("status").innerHTML = '';

    var formData = new FormData();
    for (var i = 0; i < upfile.files.length; i++) {
      sendFile = "file" + i
      formData.append(sendFile, upfile.files[i]);
    }
    formData.append("timezone", timezone);
    formData.append("logtype", logtype);
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.upload.addEventListener("progress", progressHandler, false);
    xmlhttp.addEventListener("load", completeHandler, false);
    xmlhttp.addEventListener("error", errorHandler, false);
    xmlhttp.addEventListener("abort", abortHandler, false);
    xmlhttp.open("POST", "upload", true);
    xmlhttp.send(formData);
  }
}

function progressHandler(event) {
  var percent = (event.loaded / event.total) * 100;
  document.getElementById("uploadBar").innerHTML = '<h4>Upload ...</h4><div class="progress"><div class="progress-bar progress-bar-striped active" role="progressbar" style="width: ' + Math.round(percent) + '%;">' + Math.round(percent) + '%</div></div>';
}

var parse_status = false;

function completeHandler(event) {
  if (event.target.responseText == "FAIL") {
    document.getElementById("status").innerHTML = '<div class="alert alert-danger"><strong>ERROR</strong>: Upload Failed!</div>';
  }
  if (event.target.responseText == "SUCCESS") {
    parse_status = false
    document.getElementById("uploadBar").innerHTML = '<h4>Upload ...</h4><div class="progress"><div class="progress-bar progress-bar-success progress-bar-striped" role="progressbar" style="width: 100%;">Waiting ...</div></div>';
    var loop = function() {
      if (parse_status == false) {
        setTimeout(loop, 2000);
      }
      parseEVTX();
    }
    loop();
  }
}

function errorHandler(event) {
  document.getElementById("status").innerHTML = '<div class="alert alert-danger"><strong>ERROR</strong>: Upload Failed!</div>';
}

function abortHandler(event) {
  document.getElementById("status").innerHTML = '<div class="alert alert-info">Upload Aborted</div>';
}

function parseEVTX() {
  var xmlhttp2 = new XMLHttpRequest();
  xmlhttp2.open("GET", "/log");
  xmlhttp2.send();
  xmlhttp2.onreadystatechange = function() {
    if (xmlhttp2.readyState == 4) {
      if (xmlhttp2.status == 200) {
        var logdata = xmlhttp2.responseText.split(/\r\n|\r|\n/);
        var allrecode = logdata[3].split(" ")[5].replace(".", "");
        var nowdata = logdata[logdata.length - 2];
        if (nowdata.indexOf("Now loading") != -1) {
          var recordnum = nowdata.split(" ")[3];
          var percent = (recordnum / allrecode) * 100;
          document.getElementById("uploadBar").innerHTML = '<h4>Parsing  ...</h4><div class="progress"><div class="progress-bar progress-bar-striped active" role="progressbar" style="width: ' + Math.round(percent) + '%;">' + Math.round(percent) + '%</div></div>';
        } else if (nowdata.indexOf("Script end") != -1) {
          document.getElementById("uploadBar").innerHTML = '<h4>Parsing  ...</h4><div class="progress"><div class="progress-bar progress-bar-success progress-bar-striped" role="progressbar" style="width: 100%;">SUCCESS</div></div>';
          document.getElementById("status").innerHTML = '<div class="alert alert-info"><strong>Import Success</strong>: You need to reload the web page.</div>';
          parse_status = true;
        } else if (nowdata.indexOf("[!]") != -1) {
          document.getElementById("status").innerHTML = '<div class="alert alert-danger"><strong>ERROR</strong>: EVTX parse Failed!</div>';
          parse_status = true;
        }
      } else {
        document.getElementById("status").innerHTML = '<div class="alert alert-danger"><strong>ERROR</strong>: logontracer.log status =  ' + xmlhttp2.status + '</div>';
        parse_status = true;
      }
    }
  }
}

var formatDate = function (date) {
  format = "YYYY-MM-DD hh:00:00";
  format = format.replace(/YYYY/g, date.getFullYear());
  format = format.replace(/MM/g, ('0' + (date.getMonth() + 1)).slice(-2));
  format = format.replace(/DD/g, ('0' + date.getDate()).slice(-2));
  format = format.replace(/hh/g, ('0' + date.getHours()).slice(-2));

  return format;
};
