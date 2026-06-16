var blackNum = 0,
	maxBlackNum = 30,
	initObj = null,
	macFilterType,
	moduleModel,
	pageModel,
	pageview,
	deviceInfo,
	isBindEvent = false,
	initDataList = [],
	childDeviceList = [],
	childDevice = {},
	childName,
	localhostMac;
pageview = R.pageView({ //页面初始化
	init: function () {
		top.loginOut();
		top.$(".main-dailog").removeClass("none");
		top.$(".save-msg").addClass("none");

		$("#blackTable").on("click", function () {
			$("#onlineListTable, #nodeDevice").addClass("none");
			$("#blackListTable").removeClass("none");
			blackView.init();
		});

		$("#onlineDeviceTips").on("click", function () {
			$("#onlineListTable, #nodeDevice, #mainName").removeClass("none");
			$("#blackListTable, #childName").addClass("none");
			$("#mainNode").addClass("node-active");
			$("#childNode").removeClass("node-active");
			onlineView.init();
		});
	}
});
pageModel = R.pageModel({});

/********online list****************/
var onlineView = R.moduleView({
	init: function () {
		initEvent();
		getOnlineList();
	}
});
moduleModel = R.moduleModel({});

//模块注册
R.module("onlineList", onlineView, moduleModel);


function initEvent() {
	if (isBindEvent) {
		return;
	}
	$("#onlineList").delegate(".edit-btn", "click", function () {
		showEditNameArea($(this).parents("tr")[0], $(this).parents("tr").find(".dev-name").attr("title"));
	});

	$("#onlineList").delegate(".dev-name-input", "blur", function () {
		var mac = $(this).parents("tr").attr("alt"),
			newName = $(this).parents("tr").find("input.dev-name-input").val();
		changeDevName(mac, newName);
	});

	$("#onlineList").delegate(".del", "click", function () {
		var mac = $(this).parents("tr").attr("alt");
		var devName = $(this).parents("tr").find(".dev-name").attr("title") || "";
		$(this).attr("disabled", true);
		delList(mac, devName);
	});

	$("#mainNode").on("click", function () {
		$("#childName").addClass("none");
		$("#mainName").removeClass("none");
		$("#mainNode").addClass("node-active");
		$("#childNode").removeClass("node-active");
		getOnlineList();
	})

	$("#childNode").on("click", function () {
		var value = childDevice[$("select").children('option:selected').val()];
		$("#mainName").addClass("none");
		$("#childName").removeClass("none");
		$("#childNode").addClass("node-active");
		$("#mainNode").removeClass("node-active");

		if(value && value[0].deviceId) {
			createOnlineList(value, localhostMac);
			$("#onlineDeviceTips").html(_("Attached Devices (%s)", [value.length]));
		} else {
			str = "<tr><td colspan='" + $("#onlineListTable th").length + "' >" + _("No online client") + "</td></tr>";
			$("#onlineList").html(str);
			$("#onlineDeviceTips").html(_("Attached Devices (%s)", "0"));
		}
	})

	// 切换子节点名称
	$("#childName").on("change", function () {
		var value = $(this).children('option:selected').val();
		if(childDevice[value] && childDevice[value][0].deviceId) {
			createOnlineList(childDevice[value], localhostMac);
			$("#onlineDeviceTips").html(_("Attached Devices (%s)", [childDevice[value].length]));
		} else {
			$("#onlineDeviceTips").html(_("Attached Devices (%s)", "0"));
			str = "<tr><td colspan='" + $("#onlineListTable th").length + "' >" + _("No online client") + "</td></tr>";
			$("#onlineList").html(str);
		}
	});
	isBindEvent = true;
}

function getOnlineList() {
	$.getJSON("goform/getOnlineList?" + Math.random(), initValue);
}

function createOnlineList(initDataList, localhostMac) {
	var str = "",
		i = 0,
		deviceType,
		connectTypeStr = [_("Wired"), _("2.4G"), _("5G")];
	for (i = 0; i < initDataList.length; i++) {
		deviceType = translateDeviceType(initDataList[i].linkType);
		str += "<tr alt='" + initDataList[i].deviceId + "' class='tr-row'>" +
			"<td class='edit-td'><div class='device-icon'><img src='" + deviceType.src + "'>" + showDeviceLogoString(deviceType, initDataList[i].linkType) + "</div>";
		str += "<div class='online-device-content'><div class='dev-name text-fixed' style='padding-right: 30px;'><span class='dev-name-txt'></span><img class='edit-btn edit-btn-txt-append' src='img/edit_new.png' style='width:14px;height:14px;' /></div><span class='txt-help-tips font-txt-small' data-alt='ip'>" + initDataList[i].ip + "</span><span class='line'></span><span class='txt-help-tips font-txt-small' data-alt='lineType'>"+ connectTypeStr[initDataList[i].line] +"</span></div></div></td>";

		//wisp、 router显示MAC地址、流量, 其他模式只显示MAC地址
		str += "<td>" + initDataList[i].deviceId + "</td>";
		if (top.G.workMode == "wisp" || top.G.workMode == "router") {
			str += "<td data-alt='uploadSpeed'>" + translateSpeed(initDataList[i].uploadSpeed) + "</td>" +
				"<td data-alt='downloadSpeed'>" + translateSpeed(initDataList[i].downloadSpeed) + "</td>";
		}

		// str += "<td data-alt='lineType'>" + connectTypeStr[initDataList[i].line] + "</td>";
		if (macFilterType == "black" && top.G.workMode == "router" || top.G.workMode == "wisp") {
			str += "<td data-alt='action'>" + (function () {
				//如果是访客网络
				if (initDataList[i].isGuestClient == "true") {
					return _("Guest");
				} else {
					if (initDataList[i].deviceId == localhostMac) {
						return _("Local Host");
					} else {
						return "<input type='button' class='btn del btn-action' value='" + _("Add") + "'>";
					}
				}
			})() + "</td>";
		}
		str += "</tr>";
	}
	$("#onlineList").html(str);

	var j = 0;
	$("#onlineList").find(".dev-name").each(function (i) {
		$(this).attr("title", initDataList[j].devName);
		$(this).find(".dev-name-txt").html(toHtmlCode(initDataList[j].devName));
		j++;
	});
}

function initValue(obj) {
	var str = "",
		thStr = "";
	localhostMac = obj[0].localhostMac;
	initDataList = [];
	childDeviceList = [];
	childDevice = {};
	initObj = obj;
	blackNum = obj[0].blackNum;
	macFilterType = obj[0].macFilterType || "white";
	if(top.G.nodeType == "agent" || top.G.workMode == "client+ap") {
		$("#nodeDevice").addClass("none");
	}
	if (macFilterType == "black") {
		if(top.G.nodeType == "agent") {
			$("#blackDeviceTips").remove();
		}
		if (top.G.workMode == "wisp" || top.G.workMode == "router") {

		} else {
			//黑名单 ap模式
			//$("#blackDeviceTips").remove();
			thStr = '<tr><th width="35%" >' + _("Device Name") + '</th>' +
				'<th width="25%">' + _("MAC Address") + '</th>' +
				// '<th width="20%">' + _("Access Type") + '</th>' +
				//'<th width="20%">' + _("Add") + '</th></tr>' +
				'</tr>';
			$("#onlineListTable thead").html(thStr);
		}

	} else {
		$("#blackDeviceTips").remove();
		if (top.G.workMode == "wisp" || top.G.workMode == "router") {
			//白名单 路由模式
			thStr = '<tr><th width="40%" >' + _("Device Name") + '</th>' +
				'<th width="25%">' + _("MAC Address") + '</th>' +
				'<th width="20%">' + _("Upload Speed") + '</th>' +
				'<th width="20%">' + _("Download Speed") + '</th>' +
				//'<th width="20%">' + _("Access Type") + '</th>' +
				'</tr>';
			$("#onlineListTable thead").html(thStr);
		} else {
			thStr = '<tr><th width="40%" >' + _("Device Name") + '</th>' +
				'<th width="30%">' + _("MAC Address") + '</th>' +
				//	'<th width="30%">' + _("Access Type") + '</th>' +
				'</tr>';
			$("#onlineListTable thead").html(thStr);
		}
	}

	updataData(obj);
	childNameList();
	$("#onlineDeviceTips").html(_("Attached Devices (%s)", [initDataList.length]));
	if($("#childName").hasClass("none")) {
		if (initDataList.length != 0) {
			$("#mainName").html(obj[1].mainNodeName);
			createOnlineList(initDataList, localhostMac);
		} else {
			str = "<tr><td colspan='" + $("#onlineListTable th").length + "' >" + _("No online client") + "</td></tr>";
			$("#onlineList").html(str);
		}
	} else {
		$("#childName").trigger('change');
	}

	delOnlineIp();
	top.initIframeHeight();
	initTableHeight();
}

function sortData(dataList) {
	dataList.sort((function () {
		var splitter = /^(\d+)([A-Z]*)/;
		return function (a, b) {
			a = (a.line||"").match(splitter);
			b = (b.line||"").match(splitter);
			if(a && b) {
				var anum = parseInt(a[1], 10),
					bnum = parseInt(b[1], 10);
				if (anum === bnum) {
					return a[2] < b[2] ? -1 : a[2] > b[2] ? 1 : 0;
				} else {
					return anum - bnum;
				}
			}
		};
	})());
}

function childNameList() {
	var	childNode = [],
		obj = {};
	childName = "";
	for (var i = 0; i < childDeviceList.length; i++) {
		if (!obj[childDeviceList[i].childNodeName]) {
			childNode.push(childDeviceList[i]);
			obj[childDeviceList[i].childNodeName] = true;
		}
	}

	// 子节点设备下拉框
	for (i = 0; i < childNode.length; i++) {
		childName += "<option value='" + childNode[i].childNodeName +"'>" + childNode[i].childNodeName +"</option>"
	}
	$("#childName").html(childName);
}

// 更新设备列表
function updataData(obj) {
	var i = 0,
		k = 0;
	var localhostObj = {};
	localhostMac = obj[0].localhostMac;
	initDataList = [];
	childDeviceList = [];
	childDevice = {};
	for (k = 1; k < obj.length; k++) {
		//访客网络优先显示，不管是否在黑白名单中
		if (obj[k].isGuestClient != "true") {
			if (obj[k].black == 1) {
				continue;
			}
		}

		if (obj[k].deviceId == localhostMac) {
			localhostObj = obj[k];
			continue;
		}

		if (obj[k].nodeDevice == "mainNode") {
			initDataList.push(obj[k]);
			sortData(initDataList);
		}

		if (obj[k].nodeDevice == "childNode") {
			childDeviceList.push(obj[k]);
			sortData(childDeviceList);
		}
	}

	//本机未加入黑名单时，将本机加入在线列表中
	if (localhostObj.deviceId && localhostObj.black != 1) {
		if (localhostObj.nodeDevice == "mainNode") {
			initDataList.unshift(localhostObj);
		} else {
			childDeviceList.unshift(localhostObj);
		}
	}

	childDeviceList.forEach(function(item) {
		if(!childDevice[item.childNodeName]) {
			var childArr = [];
			childArr.push(item);
			childDevice[item.childNodeName] = childArr;
		} else {
			childDevice[item.childNodeName].push(item);
		}
	})
}

function delOnlineIp() {
	if ((top.G.nodeType == "controller" && top.G.workMode == "ap") || top.G.workMode == "client+ap") {
		// $("#onlineList").find("span[data-alt='ip']").remove();
		$("#onlineList .online-device-content").css("margin-top", "10px");
	}
}

function delList(mac, devName) {
	var isParentCtrled = false;
	for (var i = initObj.length - 1; i >= 1; i--) {
		if (initObj[i].deviceId == mac) {
			if (initObj[i].parentCtrl == 1) {
				isParentCtrled = true;
				break;
			}
		}
	}

	/*if (!isParentCtrled && blackNum >= maxBlackNum) {
		//showErrMsg("msg-err",_("Up to %s device can be added to the blacklist.", [maxBlackNum]));
		showErrMsg("msg-err",_("Only a maximum of %s devices are allowed in the blacklist and parental control list.", [maxBlackNum]));
		return;
	}*/

	var data;
	data = {
		mac: mac,
		devName: devName
	}
	data = objTostring(data);
	$.post("goform/setBlackRule", data, callback);
}

function callback(str) {
	if (!top.isTimeout(str)) {
		return;
	}
	var num = $.parseJSON(str).errCode;
	clearInterval(onlineTimer);
	onlineTimer = setInterval(function () {
		updateOnlineList();
	}, 5000);
	if (num == 0) {
		updateOnlineList();
		top.showSaveMsg(num, _("Adding to the blacklist..."), 2);
	} else if (num == 1) {
		$("#onlineList .del").removeAttr("disabled");
		showErrMsg("msg-err", _("Only a maximum of %s rules are allowed.", [maxBlackNum]));
		return;
	}

}

function showEditNameArea(rowEle, name) {
	var inputWidth = $(rowEle).find(".dev-name").width() - 50 + "px";

	var htmlStr = '<div class="table-btn-group"><input type="text" class="dev-name-input" maxlength="20" style="width:' + inputWidth + '"/></div>';
	$(rowEle).find(".dev-name").html(htmlStr);
	$(rowEle).find(".dev-name .dev-name-input").val(name);
	//edit by xc
	//设备名称支持全字符，注释以下代码
	//clearDevNameForbidCode($(rowEle).find(".dev-name .dev-name-input")[0]);
}

function hideEditNameArea(rowEle, devName) {
	$(rowEle).find(".dev-name").html(toHtmlCode(devName)).append('<img class="edit-btn edit-btn-txt-append" src="img/edit_new.png" style="width:14px;height:14px;"/>');
}

function changeDevName(macAddress, newName) {
	var nodeName,
		submitStr;
	nodeName = $("#childName").hasClass("none") ? "mainNode" : "childNode";
	submitStr = "mac=" + macAddress + "&devName=" + encodeURIComponent(newName) + "&nodeName=" + nodeName;
	$("#msg-err").addClass("red").removeClass("text-success");

	//统一验证设备名称合法性
	var msg = checkDevNameValidity(newName);

	if (msg) {
		showErrMsg("msg-err", msg);
		return false;
	}

	$.post("goform/SetOnlineDevName", submitStr, function (str) {
		if ($.parseJSON(str).errCode == "0") {
			$("#msg-err").removeClass("red").addClass("text-success");
			showErrMsg("msg-err", _("Modification success"));
			$("#onlineList tr").each(function () {
				if ($(this).attr("alt") == macAddress) {
					$(this).find(".dev-name").attr("title", newName).find(".dev-name-txt").html(toHtmlCode(newName));
					hideEditNameArea(this, newName);
					return false;
				}
			});
			top.staInfo.initValue();
		} else {
			showErrMsg("msg-err", _("Modification failure"));
		}

	});
}

//更新数据
function updateOnlineList() {
	$.getJSON("goform/getOnlineList?" + Math.random(), updateSpeed);
}

var onlineTimer = setInterval(function () {
	updateOnlineList();
}, 5000);

function updateSpeed(obj) {
	var i = 1,
		len = obj.length,
		connectTypeStr = [_("Wired"), _("2.4G"), _("5G")],
		randomStr = Math.random(),
		localhostMac = obj[0].localhostMac,
		devMac,
		connectType,
		actionStr,
		$trDom,
		node,
		nodeDevice,
		childItem,
		curNodeDevice,
		curChildItem;
	for (i = 1; i < len; i++) {
		if (obj[i].isGuestClient != "true") {
			//过滤黑名单
			if (obj[i].black == 1) {
				continue;
			}
		}

		devMac = obj[i].deviceId;
		node = obj[i].childNodeName;
		nodeDevice = obj[i].nodeDevice;
		$trDom = $("#onlineList tr[alt='" + devMac + "']");
		connectType = connectTypeStr[obj[i].line];
		curNodeDevice = $("#nodeDevice").find(".node-active").attr("data-alt");
		curChildItem = $("select").children('option:selected').val();
		actionStr = (function () {
			if (obj[i].isGuestClient == "true") {
				return _("Guest");
			} else if (devMac == localhostMac) {
				return _("Local Host");
			} else {
				return "<input type='button' class='btn del btn-action' value='" + _("Add") + "'>";
			}
		})();
		//存在在线列表中时
		if ($trDom.length === 1 && ((nodeDevice == "mainNode" && nodeDevice == curNodeDevice) || (nodeDevice == "childNode" && node == curChildItem && !$("#childName").hasClass("none")))) {
			//更新速度
			if (top.G.workMode == "wisp" || top.G.workMode == "router") {
				$trDom.find("td[data-alt='uploadSpeed']").html(translateSpeed(obj[i].uploadSpeed));
				$trDom.find("td[data-alt='downloadSpeed']").html(translateSpeed(obj[i].downloadSpeed));
			}

			//更新连接类型
			$trDom.find("span[data-alt='lineType']").html(connectType);
			//更新访客、加入黑名单
			$trDom.find("td[data-alt='action']").html(actionStr);
			//更新IP
			$trDom.find("span[data-alt='ip']").html(obj[i].ip);

			$trDom.data("online.flag", randomStr);
		} else { //不存在时，说明是新增的
			if(obj[i].nodeDevice == "mainNode") {
				if(curNodeDevice == "mainNode") {
					updateList(obj, i, actionStr, randomStr);
				}
			} else {
				childItem = $("#childName option[value='" + obj[i].childNodeName + "']");
				if(childItem.length == 0) {
					childName += "<option value='" + obj[i].childNodeName +"'>" + obj[i].childNodeName +"</option>";
					$("#childName").html(childName);
				};
				if(obj[i].childNodeName == $("select").children('option:selected').val() && !$("#childName").hasClass("none")) {
					updateList(obj, i, actionStr, randomStr);
				}
			}
		}
	}
	updataData(obj);
	//删除下线的设备
	$("#onlineList").children().map(function () {
		if ($(this).data("online.flag") != randomStr) { //本次数据不在线的设备
			if ($(this).find("input[type='text'].dev-name-input").length === 0) {
				//如果此设备不在编辑状态
				$(this).remove();
			}
		}
	});

	$("#onlineDeviceTips").html(_("Attached Devices (%s)", [$("#onlineList").children().length]));
	top.initIframeHeight();
	delOnlineIp();

}

function updateList(obj,i,actionStr,randomStr) {
	var connectTypeStr = [_("Wired"), _("2.4G"), _("5G")];
	var deviceType = translateDeviceType(obj[i].linkType);
	var devname = (obj[i].devName == "" ? top.G.deviceNameSpace : obj[i].devName);
	var str = "";
	if(obj[i].deviceId) {
		str = "<tr alt='" + obj[i].deviceId + "' class='tr-row device-target'>" +
			"<td class='edit-td'><div class='device-icon'><img src='" + deviceType.src + "'>" + showDeviceLogoString(deviceType, obj[i].linkType) + "</div><div class='online-device-content'><div class='dev-name text-fixed' style='padding-right: 30px;'><span class='dev-name-txt'></span><img class='edit-btn edit-btn-txt-append' src='img/edit_new.png' style='width:14px;height:14px;' 1/></div>" +
			"<span class='txt-help-tips font-txt-small' data-alt='ip'>" + obj[i].ip + "</span><span class='line'></span><span class='txt-help-tips font-txt-small' data-alt='lineType'>"+ connectTypeStr[obj[i].line] +"</span></div></td>";
		str += "<td>" + obj[i].deviceId + "</td>";
		if (top.G.workMode == "wisp" || top.G.workMode == "router") {
			str += "<td data-alt='uploadSpeed'>" + translateSpeed(obj[i].uploadSpeed) + "</td>" +
				"<td data-alt='downloadSpeed'>" + translateSpeed(obj[i].downloadSpeed) + "</td>";
		}

		// str += "<td data-alt='lineType'>" + connectType + "</td>";
		if (macFilterType == "black" && top.G.workMode == "router" || top.G.workMode == "wisp") {
			str += "<td data-alt='action'>" + actionStr + "</td>";
		}
		str += "</tr>";
	}
	$("#onlineList").append(str);
	$("#onlineList").find(".device-target .dev-name").each(function (k) {
		$(this).attr("title", devname);
		$(this).find(".dev-name-txt").html(toHtmlCode(devname));
	});
	$("#onlineList").find(".device-target").data("online.flag", randomStr);
	$("#onlineList").find(".device-target").removeClass("device-target");
}

/*************end online list************************/

pageModel = R.pageModel({});

/********online list****************/
var blackView = R.moduleView({
	init: function () {
		getBlackList();
	}
});
moduleModel = R.moduleModel({});

//模块注册
R.module("blackList", blackView, moduleModel);

function getBlackList() {
	//$.getJSON("list.txt",initValue);
	//$.getJSON("goform/initWifiMacFilter?"+Math.random(),initValue);
	$.getJSON("goform/getBlackRuleList?" + Math.random(), initBlackList);
}

function initBlackList(obj) {
	var i = 0,
		len = obj.length,
		devname,
		str = "";
	if (len != 0) {
		for (i = 0; i < len; i++) {

			str += "<tr class='tr-row'><td class='dev-name fixed' title=''></td>" +
				"<td title='" + obj[i].deviceId + "'>" + obj[i].deviceId.toUpperCase() + "</td>" +
				"<td><input type='button' class='btn del btn-action' value='" + _("Remove") + "'></td></tr>";
		}
	} else {
		str = "<tr><td colspan=3 >" + _("The blacklist is empty.") + "</td></tr>";
	}
	if (str == "") {
		str = "<tr><td colspan=3 >" + _("The blacklist is empty.") + "</td></tr>";
	}

	$("#blackList").html(str).find(".dev-name").each(function (i) {
		devname = (obj[i].devName == "" ? top.G.deviceNameSpace : obj[i].devName);
		$(this).attr("title", devname);
		$(this).html(toHtmlCode(devname));
	});
	$("#blackList .del").on("click", delBlackList);
	top.initIframeHeight();
}

function delBlackList() {
	var mac = $(this).parents("tr").find("td").eq(1).attr("title"),
		data;

	data = "mac=" + mac;
	$.post("goform/delBlackRule", data, blackCallback);
}

function blackCallback(str) {
	if (!top.isTimeout(str)) {
		return;
	}
	var num = $.parseJSON(str).errCode;
	//clearInterval(onlineTimer);
	top.showSaveMsg(num, _("Removing from the blacklist..."), 2);
	if (num == 0) {
		getBlackList();
		//top.staInfo.initValue();
	}
}

window.onload = function () {
	deviceInfo = R.page(pageview, pageModel);
};

window.onunload = function () {
	clearInterval(onlineTimer);
};
