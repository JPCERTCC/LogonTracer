function buildGraph(graph, path, root) {
  var objidList = []
  var darkSwitch = document.getElementById("darkSwitch").checked;

  if (darkSwitch) {
    ncolor_sys = "#FF5917"
    nbcolor_sys = "#000000"
    nfcolor_sys = "#FF5917"
    ncolor_user = "#5D86FF"
    nbcolor_user = "#000000"
    nfcolor_user = "#5D86FF"
    ncolor_chenge = "#B59658"
    nfcolor_root = "#ADADAD"
    ncolor_host = "#44D37E"
    nbcolor_host = "#000000"
    nfcolor_host = "#44D37E"
    ncolor_domain = "#9573FF"
    nbcolor_domain = "#000000"
    nfcolor_domain = "#9573FF"
    ncolor_id = "#F9D46B"
    nbcolor_id = "#000000"
    nfcolor_id = "#F9D46B"
    edge_color = "#007b7d"
    ecolor = "#FAFAFA"
  } else {
    ncolor_sys = "#ff0000"
    nbcolor_sys = "#ffc0cb"
    nfcolor_sys = "#ff69b4"
    ncolor_user = "#0000cd"
    nbcolor_user = "#cee1ff"
    nfcolor_user = "#6da0f2"
    ncolor_chenge = "#404040"
    nfcolor_root = "#404040"
    ncolor_host = "#2e8b57"
    nbcolor_host = "#98fb98"
    nfcolor_host = "#3cb371"
    ncolor_domain = "#8b2e86"
    nbcolor_domain = "#fa98ef"
    nfcolor_domain = "#b23aa2"
    ncolor_id = "#8b6f2e"
    nbcolor_id = "#f9d897"
    nfcolor_id = "#b28539"
    edge_color = "#CCCCCC"
    ecolor = "#333333"
  }

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
      var rmode = document.getElementById("rankMode").checked;
      if (rmode) {
        nwidth = path[idx].properties.rank * 80 + 20
        nheight = path[idx].properties.rank * 80 + 20
      } else {
        nwidth = "25"
        nheight = "25"
      }
      if (path[idx].labels[0] == "Username") {
        nname = path[idx].properties.user
        nfsize = "10"
        nshape = "ellipse"
        ntype = "User"
        if (path[idx].properties.rights == "system") {
          ncolor = ncolor_sys
          nbcolor = nbcolor_sys
          nfcolor = nfcolor_sys
          nprivilege = "SYSTEM"
        } else {
          ncolor = ncolor_user
          nbcolor = nbcolor_user
          nfcolor = nfcolor_user
          nprivilege = "Normal"
        }
        if (path[idx].properties.status != "-") {
          ncolor = ncolor_chenge
          nshape = "octagon"
        }
        if (root == path[idx].properties.user) {
          nfcolor = nfcolor_root
        }
      }
      if (path[idx].labels[0] == "IPAddress") {
        nname = path[idx].properties.IP
        nshape = "diamond"
        nwidth = "25"
        nheight = "25"
        nfsize = "8"
        ncolor = ncolor_host
        nbcolor = nbcolor_host
        nfcolor = nfcolor_host
        ntype = "Host"
        if (root == path[idx].properties.IP) {
          nfcolor = nfcolor_root
        }
      }
      if (path[idx].labels[0] == "Domain") {
        nname = path[idx].properties.domain
        nshape = "rectangle"
        nwidth = "25"
        nheight = "25"
        nfsize = "10"
        ncolor = ncolor_domain
        nbcolor = nbcolor_domain
        nfcolor = nfcolor_domain
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
        ncolor = ncolor_id
        nbcolor = nbcolor_id
        nfcolor = nfcolor_id
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
      if (objidList.indexOf(objid) >= 0) {
        continue;
      } else {
        objidList.push(objid)
      }

      if (path[idx].type == "Event") {
        var label_count = document.getElementById("label-count").checked;
        var label_type = document.getElementById("label-type").checked;
        var label_authname = document.getElementById("label-authname").checked;
        var sourceid = parseInt(path[parseInt(idx) - 1].identity.low) + 100
        var targetid = parseInt(path[parseInt(idx) + 1].identity.low) + 100

        var filterdArray = $.grep(graph.edges,
          function(elem, index, array) {
            return (!(elem.data.source == sourceid && elem.data.target == targetid && elem.data.label == path[idx].type &&
              elem.data.eid == path[idx].properties.id && elem.data.logontype == path[idx].properties.logintype &&
              elem.data.status == path[idx].properties.status && elem.data.authname == path[idx].properties.authname));
          }
        );
        var matchArray = $.grep(graph.edges,
          function(elem, index, array) {
            return (elem.data.source == sourceid && elem.data.target == targetid && elem.data.label == path[idx].type &&
              elem.data.eid == path[idx].properties.id && elem.data.logontype == path[idx].properties.logintype &&
              elem.data.status == path[idx].properties.status && elem.data.authname == path[idx].properties.authname);
          }
        );
        var ecount = parseInt(path[idx].properties.count)
        if (Object.keys(matchArray).length) {
          ecount = ecount + parseInt(matchArray[0].data.count)
        }
        graph.edges = filterdArray
        var ename = path[idx].properties.id;
        if (label_count) {
          ename += " : " + ecount;
        }
        if (label_type) {
          ename += " : " + path[idx].properties.logintype;
        }
        if (label_authname) {
          ename += " : " + path[idx].properties.authname;
        }
        graph.edges.push({
          "data": {
            "id": objid,
            "source": sourceid,
            "target": targetid,
            "objid": objid,
            "elabel": ename,
            "label": path[idx].type,
            "distance": 5,
            "ntype": "edge",
            "eid": parseInt(path[idx].properties.id),
            "count": ecount,
            "logontype": String(path[idx].properties.logintype),
            "status": path[idx].properties.status,
            "authname": path[idx].properties.authname,
            "edge_color": edge_color,
            "ecolor": ecolor
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
  var flagTree = document.getElementById("modeTree").checked;
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
  if (flagTree) {
    flagMode = "breadthfirst";
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
        "border-width": 4,
        "border-color": "#404040"
      })
      .selector('edge').css({
        "content": "data(elabel)",
        "font-size": "8",
        "curve-style": "bezier",
        "target-arrow-shape": "triangle",
        "width": 2,
        "line-color": "data(edge_color)",
        "target-arrow-color": "data(edge_color)",
        "color": "data(ecolor)",
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

/*
qtipNode
This function generate the description text for each node.
*/
function qtipNode(ndata) {
  var qtext = 'Name: ' + ndata._private.data["nlabel"];
  if (ndata._private.data["ntype"] == "User") {
    qtext += '<br>Privilege: ' + ndata._private.data["nprivilege"];
    qtext += '<br>SID: ' + ndata._private.data["nsid"];
    qtext += '<br>Status: ' + ndata._private.data["nstatus"];
  } else if (ndata._private.data["ntype"] == "Host") {
    qtext += '<br>IP or Hostname: ' + ndata._private.data["nhostname"];
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

/*
qtipEdge
This function generate the description text for each edge.
*/
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

/*
createAllQuery
This function execute neo4j query and show all users in specific time period with graph.
The result is filtered by Event ID selected in the check box.
*/
function createAllQuery() {
  var eidStr = getQueryID();
  var dateStr = getDateRange();
  eidStr = eidStr.slice(4);
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE ' + eidStr + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
createSystemQuery
This function execute neo4j query and show all system privilege users in specific time period  with graph.
The result is filtered by Event ID selected in the check box.
*/
function createSystemQuery() {
  var eidStr = getQueryID();
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE user.rights = "system" ' + eidStr + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
createRDPQuery
This function execute neo4j query and show RDP logon users in specific time period with graph.
The result is filtered by Event ID selected in the check box.
*/
function createRDPQuery() {
  var eidStr = getQueryID();
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 10 ' + eidStr + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
createNetQuery
This function execute neo4j query and show users who logon via network in specific time period with graph.
The result is filtered by Event ID selected in the check box.
*/
function createNetQuery() {
  var eidStr = getQueryID();
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 3 ' + eidStr + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
createBatchQuery
This function execute neo4j query and show users who logon by batch script in specific time period with graph.
The result is filtered by Event ID selected in the check box.
*/
function createBatchQuery() {
  var eidStr = getQueryID();
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 4 ' + eidStr + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
createServiceQuery
This function execute neo4j query and show users who logon from windows service in specific time period with graph.
The result is filtered by Event ID selected in the check box.
*/
function createServiceQuery() {
  var eidStr = getQueryID();
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.logintype = 5 ' + eidStr + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
create14068Query
This function execute neo4j query and show users who attempted to exploit MS14-068 in specific time period with graph.
*/
function create14068Query() {
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.status =~ ".*0F" AND event.id = 4769 ' + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
createFailQuery
This function execute neo4j query and show users who failed to logon in specific time period with graph.
*/
function createFailQuery() {
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.id = 4625 ' + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
createNTLMQuery
This function execute neo4j query and show users who login with NTLM authentication in specific time period with graph.
*/
function createNTLMQuery() {
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE event.id = 4624 and event.authname = "NTLM" and event.logintype = 3 ' + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
adddelUserQuery
This function execute neo4j query and show users who had be created or deleted in specific time period with graph.
*/
function adddelUsersQuery() {
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE (user.status =~ "Created.*") OR (user.status =~ ".*Deleted.*") OR (user.status =~ ".*RemoveGroup.*") OR (user.status =~ ".*AddGroup.*") ' + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
dcsQuery
This function execute neo4j query and show users who executed DCSync or DCShadow in specific time period with graph.
*/
function dcsQuery() {
  var dateStr = getDateRange();
  var queryStr = 'MATCH (user)-[event:Event]-(ip) WHERE (user.status =~ ".*DCSync.*") OR (user.status =~ ".*DCShadow.*") ' + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
dcsQuery
This function execute neo4j query and show users who executed DCSync or DCShadow in specific time period with graph.
*/
function createDomainQuery() {
  var queryStr = 'MATCH (user)-[event:Group]-(ip) RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

/*
policyQuery
This function execute neo4j query and show users who changed the audit policy in specific time period with graph.
*/
function policyQuery() {
  var dateStr = getDateRange();
  dateStr = dateStr.slice(5);
  queryStr = 'MATCH (user)-[event:Policy]-(ip) WHERE ' + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, "noRoot");
}

function createRankQuery(setStr, qType) {
  var dateStr = getDateRange();
  if (qType == "User") {
    whereStr = 'user.user = "' + setStr + '" ';
  }
  if (qType == "Host") {
    whereStr = 'ip.IP = "' + setStr + '" ';
  }

  if (qType != "Domain") {
    eidStr = getQueryID();
    queryStr = 'MATCH (user)-[event:Event]-(ip)  WHERE (' + whereStr + ') ' + eidStr + dateStr + ' RETURN user, event, ip';
  } else {
    queryStr = 'MATCH (user)-[event:Group]-(ip) WHERE user.domain = "' + setStr + '" RETURN user, event, ip'
  }
  //console.log(queryStr);
  executeQuery(queryStr, setStr);
}

/*
getQueryID
This function generate the neo4j query strings to filter Windows Event ID and ID count.
*/
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

/*
getDateRange
This function generates a neo4j query strings to filter events in specific time period.
*/
function getDateRange() {
  var fromDate = new Date(document.getElementById("from-date").value).getTime() / 1000;
  var toDate = new Date(document.getElementById("to-date").value).getTime() / 1000;
  var dateStr = " AND (event.date >= " + fromDate + " AND event.date <= " + toDate + ")";

  return dateStr;
}

/*
createQuery
This function generates a neo4j query strings from search box and execute the query.
*/
function createQuery() {
  var selectVal = document.getElementById("InputSelect").value;
  var setStr = document.getElementById("query-input").value;
  var dateStr = getDateRange();

  if (selectVal == "Username") {
    whereStr = 'user.user =~ "' + setStr + '" ';
  } else if (selectVal == "IPAddress") {
    whereStr = 'ip.hostname =~ "' + setStr + '" ';
  } else {
    whereStr = 'ip.IP =~ "' + setStr + '" ';
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
  queryStr = 'MATCH (user)-[event:Event]-(ip)  WHERE (' + whereStr + ') ' + eidStr + dateStr + ' RETURN user, event, ip';
  //console.log(queryStr);
  executeQuery(queryStr, setStr);
}

/*
searchPath
This function execute a neo4j query strings to search the shortest path to system privilege in specific time period.
*/
function searchPath() {
  var setStr = document.getElementById("query-input").value;
  var dateStr = getDateRange();
  dateStr = dateStr.slice(5);

  queryStr = 'MATCH (from:Username { user:"' + setStr + '" }), (to:Username { rights:"system"}), p = shortestPath((from)-[:Event*]-(to)) \
              WITH p \
              MATCH (user:Username) WHERE user IN nodes(p) \
              MATCH (ip:IPAddress) WHERE ip IN nodes(p) \
              MATCH (user)-[event]-(ip) WHERE ' + dateStr + ' \
              RETURN user, ip, event'

  //console.log(queryStr);
  executeQuery(queryStr, setStr);
}

/*
sendQuery
This function sends the query to neo4j.
If the query success, this function build the graph and draw it from the neo4j query result.
*/
function sendQuery(queryStr, root) {
  var graph = {
    "nodes": [],
    "edges": []
  };

  var loading = document.getElementById('loading');
  loading.classList.remove('loaded');

  var session = driver.session();
  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        //console.log(record.get('user'), record.get('event'), record.get('ip'));
        graph = buildGraph(graph, [record.get("user"), record.get("event"), record.get("ip")], root);
      },
      onCompleted: function() {
        session.close();
        if (graph.nodes.length == 0) {
          searchError();
          loading.classList.add("loaded");
        } else {
          //console.log(graph);
          if (root == "noRoot") {
            rootNode = graph.nodes[0].data.id;
          } else {
            for (var i = 0; i < graph.nodes.length; i++) {
              if (graph.nodes[i].data.nlabel == root) {
                rootNode = graph.nodes[i].data.id;
              }
            }
          }
          drawGraph(graph, rootNode);
        }
      },
      onError: function(error) {
        searchError();
        console.log("Error: ", error);
      }
    });
}

/*
executeQuery
This function executes the neo4j query.
*/
function executeQuery(queryStr, root) {
  var countStr = queryStr.replace("user, event, ip", "COUNT(event)");

  var session = driver.session();
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
          sendQuery(queryStr, root);
        }
      },
      onError: function(error) {
        searchError();
        console.log("Error: ", error);
      }
    });
}

/*
diffQuery
This function compare 2 days events from neo4j.
If the query success, this function build the graph and draw it from the neo4j query result.
*/
function diffQuery() {
  var graph1 = {
    "nodes": [],
    "edges": []
  };

  root = "noRoot"
  var date1st = new Date(document.getElementById("from-day").value).getTime() / 1000;

  queryStr1st = 'MATCH (user)-[event:Event]-(ip)  WHERE event.date >= ' + date1st + ' AND event.date <= ' + (date1st + 86400) + ' RETURN user, event, ip';

  var session = driver.session();
  session.run(queryStr1st)
    .subscribe({
      onNext: function(record) {
        //console.log(record.get('user'), record.get('event'), record.get('ip'));
        graph1 = buildGraph(graph1, [record.get("user"), record.get("event"), record.get("ip")], root);
      },
      onCompleted: function() {
        session.close();
        if (graph1.nodes.length == 0) {
          searchError();
        } else {
          diffNext(graph1);
        }
      },
      onError: function(error) {
        searchError();
        console.log("Error: ", error);
      }
    });
}

function diffNext(graph1) {
  var graph2 = {
    "nodes": [],
    "edges": []
  };

  root = "noRoot"
  var date2nd = new Date(document.getElementById("to-day").value).getTime() / 1000;

  queryStr2nd = 'MATCH (user)-[event:Event]-(ip)  WHERE event.date >= ' + date2nd + ' AND event.date <= ' + (date2nd + 86400) + ' RETURN user, event, ip';

  var loading = document.getElementById('loading');
  loading.classList.remove('loaded');

  var session = driver.session();
  session.run(queryStr2nd)
    .subscribe({
      onNext: function(record) {
        //console.log(record.get('user'), record.get('event'), record.get('ip'));
        graph2 = buildGraph(graph2, [record.get("user"), record.get("event"), record.get("ip")], root);
      },
      onCompleted: function() {
        session.close();
        if (graph2.nodes.length == 0) {
          searchError();
          loading.classList.add("loaded");
        } else {
          graph2.edges = getArrayDiff(graph1, graph2);
          graph2.nodes = nodeConcat(graph1, graph2);
          if (graph2.edges.length > 0) {
            drawGraph(graph2, graph2.nodes[0].data.id);
          } else{
            searchError();
            loading.classList.add("loaded");
          }
        }
      },
      onError: function(error) {
        searchError();
        console.log("Error: ", error);
      }
    });
}

function getArrayDiff(arr1, arr2) {
  let arr = arr1.edges.concat(arr2.edges);
  return arr.filter((v, i)=> {
    return !(arr1.edges.findIndex(obj => obj.data.source === v.data.source, obj => obj.data.target === v.data.target) >= 0 &&
             arr2.edges.findIndex(obj => obj.data.source === v.data.source, obj => obj.data.target === v.data.target) >= 0);
  });
}

function nodeConcat(arr1, arr2) {
  let arr = arr1.nodes.concat(arr2.nodes);
  return arr.filter((v, i)=> {
    console.log(arr2.edges)
    console.log(arr)
    return (arr2.edges.findIndex(obj => obj.data.source === v.data.id) >= 0 ||
            arr2.edges.findIndex(obj => obj.data.target === v.data.id) >= 0);
  });
}

var setqueryStr = "";

function contQuery() {
  sendQuery(setqueryStr, "noRoot");
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
  var html = '<div><table class="table table-hover"><thead class="thead-light"><tr class="col-sm-2 col-md-2">\
              <th class="col-sm-1 col-md-1">Rank</th><th class="col-sm-1 col-md-1">' + dataType +
    '</th></tr></thead><tbody class="col-sm-2 col-md-2">';
  var startRunk = currentPage * 10;
  queryStr = queryStr + " SKIP " + startRunk + " LIMIT " + 10;

  var session = driver.session();
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

  var session = driver.session();
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

  var session = driver.session();
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
  var html = '<div class="table-responsive"><table class="table table-hover table-bordered table-sm table-striped table-wrapper" style="background-color:#EEE;"><thead class="thead-light"><tr>\
                    <th ' + span + '>Username</th>';

  for (i = 0; i < chartArray.length; i++) {
    if (chartArray[i]) {
      chartArray[i].destroy();
    }
  }

  var session = driver.session();
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

        if (darkSwitch) {
          normal_color = "#4d0715"
          low_color = "#800b23"
          mid_color = "#b31031"
          high_color = "#dc143c"
        } else {
          normal_color = "#ffeaee"
          low_color = "#ffbaee"
          mid_color = "#ff8aee"
          high_color = "#ff5aee"
        }

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
        for (i = 1; i < rangeHours; i++) {
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
                html += '<td bgcolor="' + high_color + '">' + rowdata[j].split(".")[0] + '</td>';
              } else if (alerts[j] > 16) {
                html += '<td bgcolor="' + mid_color + '">' + rowdata[j].split(".")[0] + '</td>';
              } else if (alerts[j] > 13) {
                html += '<td bgcolor="' + low_color + '">' + rowdata[j].split(".")[0] + '</td>';
              } else if (alerts[j] > 10) {
                html += '<td bgcolor="' + normal_color + '">' + rowdata[j].split(".")[0] + '</td>';
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
                  html += '<td bgcolor="' + high_color + '">' + rowdata[k].split(".")[0] + '</td>';
                } else if (alerts[k] > 16) {
                  html += '<td bgcolor="' + mid_color + '">' + rowdata[k].split(".")[0] + '</td>';
                } else if (alerts[k] > 13) {
                  html += '<td bgcolor="' + low_color + '">' + rowdata[k].split(".")[0] + '</td>';
                } else if (alerts[k] > 10) {
                  html += '<td bgcolor="' + normal_color + '">' + rowdata[k].split(".")[0] + '</td>';
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

        $(function() {
          $(".table.table-wrapper").floatThead({
            responsiveContainer: function($table) {
              return $table.closest(".table-responsive");
            }
          });
        });
      },
      onError: function(error) {
        searchError();
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

  var session = driver.session();
  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        dateData = record.get("date");
        nodeData = record.get("user");
        users.push([nodeData.properties.user, nodeData.properties.counts4624, nodeData.properties.counts4625, nodeData.properties.counts4768,
          nodeData.properties.counts4769, nodeData.properties.counts4776, nodeData.properties.detect
        ]);
        starttime = dateData.properties.start;
        endtime = dateData.properties.end;
      },
      onCompleted: function() {
        session.close();
        var canvasArray = addCanvas(users);
        var startDate = new Date(starttime);
        var rangeHours = Math.floor((Date.parse(endtime) - Date.parse(starttime)) / (1000 * 60 * 60)) + 1;
        for (i = 1; i <= rangeHours; i++) {
          dates.push(formatDate(startDate))
          startDate.setHours(startDate.getHours() + 1);
        }

        for (i = 0; i < users.length; i++) {
          var ctx = canvasArray[i].getContext("2d");
          chartArray[i] = new Chart(ctx, {
            type: "line",
            data: {
              labels: dates,
              datasets: [{
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
                  }
                ]
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
        searchError();
        console.log("Error: ", error);
      }
    });
}

function addCanvas(users) {
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

/*
logdeleteCheck
push alert if the event log had deleted.
*/
function logdeleteCheck() {
  var queryStr = "MATCH (date:Deletetime) RETURN date";
  var ddata = "";

  var session = driver.session();
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
            '<div class="alert alert-danger alert-dismissible mt-3" id="alertfadeout" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="close">\
            <span aria-hidden="true">×</span></button><strong>IMPORTANT</strong>: Delete Event Log has detected! If you have not deleted the event log, the attacker may have deleted it.\
            <br>DATE: ' + delDate + '  DOMAIN: ' + delDomain + '  USERNAME: ' + delUser + '</div>';
        }
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

/*
searchError
push alert if search has failed.
*/
function searchError() {
  var elemMsg = document.getElementById("error");
  elemMsg.innerHTML =
    '<div class="alert alert-warning alert-dismissible mt-3" id="alertfadeout" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="close">\
    <span aria-hidden="true">×</span></button><strong>WARNING</strong>: Search failed!</div>';
  $(document).ready(function() {
    $('#alertfadeout').fadeIn(2000).delay(4000).fadeOut(2000);
  });
}

/*
file_upload
Upload EVTX file or XML file to LogonTracer Server.
*/
function file_upload() {
  var upfile = document.getElementById("lefile");
  var timezone = document.getElementById("utcTime").value;
  var logtype = document.getElementById("logType").value;
  var addlog = document.getElementById("add_log").checked;

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
    formData.append("addlog", addlog);
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

/*
parseEVTX
Get EVTX parsing progress from log.
*/
function parseEVTX() {
  var xmlhttp2 = new XMLHttpRequest();
  xmlhttp2.open("GET", "/log");
  xmlhttp2.send();
  xmlhttp2.onreadystatechange = function() {
    if (xmlhttp2.readyState == 4) {
      if (xmlhttp2.status == 200) {
        var logdata = xmlhttp2.responseText.split(/\r\n|\r|\n/);
        for (i = 0; i < logdata.length; i++) {
          if (logdata[i].indexOf("Last record number") != -1) {
            var allrecode = logdata[i].split(" ")[5].replace(".", "");
            break;
          }
        }
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

/*
loaddate
load date info from neo4j
*/
function loaddate() {
  var queryStr = 'MATCH (date:Date) RETURN date';

  var session = driver.session();
  session.run(queryStr)
    .subscribe({
      onNext: function(record) {
        dateData = record.get("date");
        starttime = dateData.properties.start;
        endtime = dateData.properties.end;
      },
      onCompleted: function() {
        session.close();
        var minDate = new Date(starttime);
        var maxDate = new Date(endtime);
        maxDate.setTime(maxDate.getTime() + 3600000);

        var minDay = new Date(starttime);
        var maxDay = new Date(endtime);
        var setminDate = new Date(minDay.getFullYear(), minDay.getMonth(), minDay.getDate())
        minDay.setTime(setminDate.getTime());
        var setmaxDate = new Date(maxDay.getFullYear(), maxDay.getMonth(), maxDay.getDate())
        maxDay.setTime(setmaxDate.getTime());

        $('.fromdate').datetimepicker({
          locale: "en",
          format: "YYYY-MM-DD HH:00:00",
          useCurrent: false,
          defaultDate: minDate,
          maxDate: maxDate,
          minDate: minDate
        });

        $('.todate').datetimepicker({
          locale: "en",
          format: "YYYY-MM-DD HH:00:00",
          useCurrent: false,
          defaultDate: maxDate,
          maxDate: maxDate,
          minDate: minDate
        });

        $('.fromday').datetimepicker({
          locale: "en",
          format: "YYYY-MM-DD",
          useCurrent: false,
          defaultDate: minDay,
          maxDate: maxDay,
          minDate: minDay
        });

        $('.today').datetimepicker({
          locale: "en",
          format: "YYYY-MM-DD",
          useCurrent: false,
          defaultDate: maxDay,
          maxDate: maxDay,
          minDate: minDay
        });
      },
      onError: function(error) {
        console.log("Error: ", error);
      }
    });
}

var formatDate = function(date) {
  format = "YYYY-MM-DD hh:00:00";
  format = format.replace(/YYYY/g, date.getFullYear());
  format = format.replace(/MM/g, ('0' + (date.getMonth() + 1)).slice(-2));
  format = format.replace(/DD/g, ('0' + date.getDate()).slice(-2));
  format = format.replace(/hh/g, ('0' + date.getHours()).slice(-2));

  return format;
};
