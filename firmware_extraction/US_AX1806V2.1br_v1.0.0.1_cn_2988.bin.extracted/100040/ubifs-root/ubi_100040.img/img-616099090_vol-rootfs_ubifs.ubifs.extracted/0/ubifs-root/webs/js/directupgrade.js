var language = B.getLang();
var G = {};

function initDirectUpgrade() {
  $.getJSON("goform/cloudv2?module=wansta&opt=query&rand=" + Math.random(), function (obj) {
    if (obj.wan_sta == 0) {
      $("#status_checking").html(_("Failed to access the internet. Please check the internet connection."));
    } else {
      $.getJSON(
        "goform/cloudv2?module=olupgrade&opt=queryversion&rand=" + new Date().toTimeString(),
        onlineQueryVersion
      );
    }
  });
}

function onlineErrCode(num) {
  var result = "";
  switch (num) {
    case 0:
      break;
    case 1:
      result = _("Unknown error.");
      break;
    case 2:
      result = _("JSON data is too long.");
      break;
    case 3:
      result = _("Failed to allocate memory. The available memory is not enough.");
      break;
    case 4:
      result = _("Connection failed.");
      break;
    case 5:
    case 6:
      result = _("Failed to connect to the socket.");
      break;
    case 7:
    case 8:
      result = _("Failed to run the command.");
      break;
    case 9:
      result = _("Invalid command.");
      break;
    case 10:
    case 11:
    case 12:
      result = _("Failed to analyze, package, or detect data.");
      break;
    case 13:
    case 14:
    case 17:
      result = _("Failed to connect to the server.");
      break;
    case 15:
      result = _("Authentication failure.");
      break;
    case 16:
      result = _("The Tenda WiFi App feature is disabled.");
      break;
    case 18:
      result = _("The cloud server is busy updating data or testing speeds.");
      break;
    case 19:
      result = _("Connecting to the server...");
      break;
  }

  return result;
}

// function onlineQueryVersion(obj) {
//   var ver_info = obj.ver_info,
//     descriptionArr = [];
//   var result = onlineErrCode(ver_info.err_code);
//   if (ver_info.err_code == 19) {
//     $("#status_checking").removeClass("none").html(result);
//     clearTimeout(G.time);
//     clearTimeout(G.onlineTimer);
//     G.onlineTimer = setTimeout(function () {
//       $.getJSON("goform/cloudv2?module=wansta&opt=query&rand=" + Math.random(), function (obj) {
//         if (obj.wan_sta == 0) {
//           $("#status_checking").html(_("Failed to access the internet. Please check the internet connection."));
//         } else {
//           $.getJSON(
//             "goform/cloudv2?module=olupgrade&opt=queryversion&rand=" + new Date().toTimeString(),
//             onlineQueryVersion
//           );
//         }
//       });
//     }, 2000);
//     return;
//   }

//   if (result == "") {
//     switch (ver_info.resp_type) {
//       case 0:
//         //获取到新版本，显示版本信息，根据当前语言来显示
//         $("#status_checking, #status_progress, #download_note, #upgrade_err").addClass("none");
//         $("#status_checked, #download_soft").removeClass("none");
//         $("#download_soft").prop("disabled", false);
//         //显示信息
//         // $("#new_fw_ver").html(ver_info.detail.newest_ver);
//         // $("#new_fw_date").html(ver_info.detail.update_date);
//         // var description = ver_info.detail.description;
//         // if (language == "en") {
//         //   description = ver_info.detail.description_en;
//         // } else if (language == "cn") {
//         //   description = ver_info.detail.description;
//         // } else if (language == "zh") {
//         //   description = ver_info.detail.description_zh_tw;
//         // }
//         // if (description) {
//         //   descriptionArr = description.join("").split("\n");
//         // } else {
//         //   descriptionArr = ver_info.detail.description[0].split("\n");
//         // }
//         // $("#releaseNote").html("");
//         // for (var i = 0; i < descriptionArr.length; i++) {
//         //   $("#releaseNote").append("<li>" + descriptionArr[i] + "</li>");
//         // }

//         break;
//       case 1:
//         //没有新版本
//         //$("#status_checking").html(_("No later version is available."));
//         //$("#download_soft").addClass("none");
//         break;
//     }
//   } else {
//     $("#status_checking").html(result);
//   }

//   top.initIframeHeight();
// }

function dowloadSoft() {
  //if (window.confirm(_("When download is complete, the router starts the upgrade automatically. Keep the router powered on during the upgrade to prevent damaging the router."))) {

  //去掉关闭操作
  top.$("body").undelegate("#gbx_overlay", "click");
  //不允许跳转页面
  top.$(".iframe-close").addClass("none");
  G.startUpgrade = true;
  $('input[name="upgradeType"]').attr("disabled", true);
  // 如果主节点没有升级需要，则不处理后续
  if (!G.needUpdate) {
    $("#download_soft").prop("disabled", true);
    // 调用接口通知升级
    $.getJSON("goform/cloudv2?module=wansta&opt=query&rand=" + Math.random(), function (obj) {
      if (obj.wan_sta == 0) {
        $("#status_checking").html(_("Failed to access the internet. Please check the internet connection."));
      } else {
        $.getJSON("goform/cloudv2?module=olupgrade&opt=queryupgrade&rand=" + new Date().toTimeString());
      }
    });
    return;
  }

  clearTimeout(G.onlineTimer);

  $("#download_soft").prop("disabled", true);
  $("#download_soft, #status_progress, #download_note, #status_checked").addClass("none");
  $("#status_checking").removeClass("none").html(_("Downloading..."));

  $.getJSON("goform/cloudv2?module=wansta&opt=query&rand=" + Math.random(), function (obj) {
    if (obj.wan_sta == 0) {
      $("#status_checking").html(_("Failed to access the internet. Please check the internet connection."));
      $("#download_soft").prop("disabled", false);
      $('input[name="upgradeType"]').attr("disabled", false);
      top.$(".iframe-close").removeClass("none");
      top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);
    } else {
      $.getJSON(
        "goform/cloudv2?module=olupgrade&opt=queryupgrade&rand=" + new Date().toTimeString(),
        queryUpgradeStatus
      );
    }
  });
  //}
}

function queryUpgradeStatus(obj) {
  var num = 0;

  if (typeof obj == "string" && obj.indexOf("!DOCTYPE html") >= 0) {
    //被重置了页面，说明升级有问题
    num = -1;
  }
  if (num == 0) {
    showOnlineUp(obj);
  } else {
    $("#download_soft").prop("disabled", false);
    top.$(".iframe-close").removeClass("none");
    top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);
    top.$("#page-message").html(_("Upgrade error. Please check the internet connection status."));
    setTimeout(function () {
      top.$(".main-dailog").removeClass("none");
      //显示页面，隐藏保存进度条
      top.$(".save-msg").addClass("none");
    }, 1000);
  }
}

function showOnlineUp(obj) {
  var update_info = {},
    wait_info = {},
    up_info = obj.up_info;

  var result = onlineErrCode(up_info.err_code);

  if (up_info.err_code == 19) {
    $("#status_checking").removeClass("none").html(result);

    checkingStatus(2000);
    return;
  }

  if (result == "") {
    $("#upgrade_err").addClass("none").html("");
    switch (up_info.resp_type) {
      case 0:
        //正在询问升级服务器，即正在准备下载
        $('input[name="upgradeType"]').attr("disabled", true);

        $("#download_soft, #download_note, #status_checked").addClass("none");

        //$("#status_checking").removeClass("none").html(_("Downloading..."));
        $("#status_checking").html("");
        $("#status_progress").removeClass("none");
        $("#progressMsg").html(_("Downloading..."));
        $("#progress_bar").css("width", "0%");
        $("#progress_num .progressNum").html("0%");

        //继续检测
        checkingStatus(5000);
        break;
      case 1:
        //内存不足
        top.$(".iframe-close").removeClass("none");
        top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);
        $('input[name="upgradeType"]').attr("disabled", false);
        $("#status_progress,#download_soft,#download_note").addClass("none");
        $("#status_checking").html("");
        $("#upgrade_err")
          .html(_("The available memory is not enough. Please reboot the router before downloading data."))
          .removeClass("none");
        //错误后 3秒后恢复 之前状态
        setTimeout(function(){
          $("#upgrade_err").html("").addClass("none");
          $("#download_soft,#status_checking").removeClass("none");
        },3000)

        break;
      case 2:
        //路由器在排队升级
        $('input[name="upgradeType"]').attr("disabled", true);
        $("#download_soft, #status_progress , #download_note, #status_checked").addClass("none");

        wait_info = up_info.detail;
        $("#status_checking")
          .removeClass("none")
          .html(_("%s user(s) is/are queuing. You may need to wait %s seconds.", [wait_info.pos, wait_info.time]));
        checkingStatus(2000);
        break;
      case 3:
        //路由器正在下载固件
        $('input[name="upgradeType"]').attr("disabled", true);
        $("#status_checking,#download_soft, #status_checked").addClass("none");

        $("#status_progress, #download_note").removeClass("none");
        $("#progressMsg").html(_("Downloading..."));
        $("#progress_num .progressNum").removeClass("none");
        $("#downLoadTime").removeClass("none");

        var progress = parseInt((up_info.detail.recved / up_info.detail.fw_size) * 100, 10);

        $("#progress_bar").css("width", progress + "%");
        $("#progress_num .progressNum").html(progress + "%");
        $("#remainingTime").text(formatSeconds(up_info.detail.sec_left).replace(/&nbsp;/g, " "));

        checkingStatus(2000);
        break;
      case 4:
        //路由器正在烧写固件
        $('input[name="upgradeType"]').attr("disabled", true);
        //下载完成后，隐藏更新内容，显示正在准备升级
        $("#status_checked, #download_soft, #download_note").addClass("none");
        $("#status_checking,#downLoadTime").addClass("none");
        
        //$("#status_checking").removeClass("none").html(_("Preparing for the upgrade... Please wait."));
        // 如果当前有子节点正在下载中 显示 当前等待子节点下载，并且在没有子节点升级后显示进度条
        if(G.childUpload){
          $("#status_checking").removeClass("none").html(_("等待子节点下载完成中..."));
          G.waitReboot = true;
          $("#status_progress").addClass("none");
        }else{
          $("#status_progress").removeClass("none");
          //top.$(".main-dailog").addClass("none");
          onlineProgress();
        }
        
        break;

      default:
        top.$(".iframe-close").removeClass("none");
        top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);
        $('input[name="upgradeType"]').attr("disabled", false);
        top.$("#page-message").html(_("Upgrade failure."));
        $("#status_checking").html(_("Upgrade failure."));

        setTimeout(function () {
          top.$(".main-dailog").removeClass("none");
          //显示页面，隐藏保存进度条
          $("#download_soft,#status_checking").removeClass("none");
        }, 1000);

        break;
    }
  } else {
    $("#status_checking, #status_progress, #download_note").addClass("none");
    $("#status_checking").html("");
    $("#download_soft").removeClass("none");
    $("#status_checked").removeClass("none");
    $("#upgrade_err").removeClass("none").html(result);
    top.$(".iframe-close").removeClass("none");
    top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);

    //错误后 3秒后恢复 之前状态
    setTimeout(function(){
      $("#upgrade_err").html("").addClass("none");
      $("#download_soft,#status_checking").removeClass("none");

    },3000)

  }

  top.initIframeHeight();
}

function onlineProgress() {
  var rebootTimer = null,
    percent = 0;
  $("#progress_bar").css("width", 0);
  $("#progress_num .progressNum").text("0%");
  $("#progressMsg").html(_("Upgrading... Please wait."));
  $("#download_note").removeClass("none");

  function rebootTime(percent) {
    $("#progress_bar").css("width", percent + "%");
    $("#progress_num .progressNum").text(percent + "%");
    $("#progress_num").addClass("txt-center");
    rebootTimer = setTimeout(function () {
      rebootTime(percent);
    }, 1450);

    if (percent >= 100) {
      clearTimeout(rebootTimer);
      top.jumpTo(window.location.host);
      return;
    } else if (percent >= 80) {
      $("#progressMsg").html(_("Rebooting... Please wait."));
    }
    percent++;
  }

  rebootTime(0);
}

function checkingStatus(time) {
  clearTimeout(G.time);
  clearTimeout(G.onlineTimer);
  G.time = setTimeout(function () {
    $.getJSON("goform/cloudv2?module=wansta&opt=query&rand=" + Math.random(), function (obj) {
      if (obj.wan_sta == 0) {
        top.$(".iframe-close").removeClass("none");
        top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);
        if ($("#status_progress").hasClass("none")) {
          $("#status_checking").html(_("Failed to access the internet. Please check the internet connection."));
        } else {
          $(".status-tips").html(_("Failed to access the internet. Please check the internet connection."));
          $(".txt-help-tips,#downLoadTime,.progressNum").addClass("none");
          $("#progressMsg").html(_("Upgrade failure."));
          $("#progress_bar").css("background", "#ccc");

          //错误后 3秒后恢复 之前状态
          setTimeout(function(){
            $("#upgrade_err").html("").addClass("none");
            $(".status-tips").html(_("Do not power off the router during the upgrade."));
            $("#progress_bar").css("width", "0%");
            $("#status_progress, #download_note").addClass("none");
            $("#download_soft,#status_checked,#status_checking").removeClass("none");
            $(".txt-help-tips,#downLoadTime,.progressNum").removeClass("none");
            $("#progress_bar").css("background", "#0c7cfa");
          },3000)
        }
      } else {
        $.getJSON("goform/cloudv2?module=olupgrade&opt=queryupgrade&rand=" + new Date().toTimeString(), showOnlineUp);
      }
    });
  }, time);
}

function changeUpgradeType() {
  if ($("#local_upgrade").prop("checked")) {
    setUpdateTimer(false);
    $("#local_upgrade_wrap").removeClass("none");
    $("#online_upgrade_wrap").addClass("none");
  } else {
    // initDirectUpgrade();
    // 启动获取在线升级信息
    setUpdateTimer(true);
    $("#online_upgrade_wrap").removeClass("none");
    $("#local_upgrade_wrap").addClass("none");
  }
  top.initIframeHeight();
}

function callback(obj) {
  $("#cur_fw_ver").html(obj.cur_fw_ver);
}

function noUpgradeFirm() {
  var dataStr = "";
  if ($("#noUpdateTips").length > 0 && $("#noUpdateTips")[0].checked) {
    dataStr = "action=1&newVersion=" + $("#new_fw_ver").html();
    $.GetSetData.setData("goform/setNotUpgrade", dataStr, function () {
      top.closeIframe();
    });
  } else {
    top.closeIframe();
  }
}

function initEvent() {
  $("[name='upgradeType']").on("click", changeUpgradeType);
  $("#sys_upgrade").on("click", function () {
    if ($("#upgradeFile").val() == "") {
      //if($("#cur_fw_ver").html() == $("#new_fw_ver").html()) {
      showErrMsg("msg-err", _("Please select a firmware file for upgrading the router."));
      G.index = 1;
      return false;
      //}
      //$.post("goform/SysToolSetUpgrade", "action=0",callbackUpgrade)
    } else {
      document.forms[0].submit();
      top.showSaveMsg("888", _("Saving..."));
      // //window.location.href = "redirect.html?4"
      $("#sys_upgrade").attr("disabled", true);
    }
  });

  $("#noUpdate").on("click", noUpgradeFirm);

  $("#download_soft").on("click", dowloadSoft);

  //重新定义关闭弹出框事件
  top.$(".iframe-close").off("click");
  top.$(".iframe-close").on("click", function () {
    top.$(".iframe-close").off("click").on("click", top.closeIframe);
    noUpgradeFirm();
  });

  $.getJSON("goform/SysToolGetUpgrade?" + Math.random(), callback);
}

function initUpgrade() {
  var msg = location.search.substring(1) || "0";
  //1001 格式错误
  //1002 CRC校验失败
  //1003 文件大小错误
  //1004 升级失败
  //1005 内存不足，请重启路由器
  top.$(".save-msg").addClass("none");
  if ($("#local_upgrade").length > 0) {
    $("#local_upgrade").prop("checked", true);
    $("#local_upgrade_wrap").removeClass("none");
    $("#online_upgrade_wrap").addClass("none");
  }

  if (msg == "1001") {
    $("#msg-err").html(_("Format error!"));
  } else if (msg == "1002") {
    $("#msg-err").html(_("CRC check Failure"));
  } else if (msg == "1003") {
    $("#msg-err").html(_("File size error"));
  } else if (msg == "1004") {
    $("#msg-err").html(_("Fail to upgrade it!"));
  } else if (msg == "1005") {
    $("#msg-err").html(_("Internal memory is not enough. Please reboot the router before upgrading."));
  } else {
    if ($("#online_upgrade").length > 0) {
      $("#online_upgrade").prop("checked", true);
      $("#online_upgrade_wrap").removeClass("none");
      $("#local_upgrade_wrap").addClass("none");
    }
    setUpdateTimer(true);
    //initDirectUpgrade();
  }
  $("#sys_upgrade").removeAttr("disabled");
  top.$(".main-dailog").removeClass("none");
}

function updateUpgradeBtn() {
  // 有新版本 有网络 没有子节点处于升级状态 并且没有正在升级状态的时候
  if (G.hasNewVersion && G.hasWan && G.noUpgrade & !G.startUpgrade) {
    $("#download_soft").prop("disabled", false);
  } else {
    $("#download_soft").prop("disabled", true);
  }
}

// 获取升级节点的信息
function getUpdateInfo() {
  $.getJSON("goform/cloudv2?module=wansta&opt=query&rand=" + Math.random(), function (obj) {
    if (obj.wan_sta == 0) {
      G.hasWan = false;
      G.startUpgrade = false;
      top.$(".iframe-close").removeClass("none");
      top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);
      $('input[name="upgradeType"]').attr("disabled", false);
      $("#status_checking").html(_("Failed to access the internet. Please check the internet connection."));
    } else {
      G.hasWan = true;
      // 查询是否可以连接服务器 等点击 开始升级按钮后 就不查询服务器了
      if(!G.startUpgrade){
        $("#status_checking").html("");
        $.getJSON(
          "goform/cloudv2?module=olupgrade&opt=queryversion&rand=" + new Date().toTimeString(),
          onlineQueryVersion
        );
      }
    }
    updateUpgradeBtn();
  });

  var api = "goform/getOnlineUpdateStatus?"+( G.startUpgrade? "opt=queryupgrade&":"") +"rand=" + Math.random();
  // 优先上面的接口
  setTimeout(function(){
    $.getJSON(api, showTable);
  },1000)
}

function onlineQueryVersion(obj) {
  var ver_info = obj.ver_info;
  var result = onlineErrCode(ver_info.err_code);
  G.checkServer = !result;

  $("#status_checking").html(result);
}

// 显示节点信息
function showTable(obj) {
  var len = obj.length,
    i = 0,
    str = "";

  // 记录是否有新版本
  G.hasNewVersion = false;
  // 记录主节点是否有在线升级
  G.needUpdate = false;
  // 记录是否有版本升级
  G.noUpgrade = true;
  // 记录是否之前是默认状态 就是都是在线  
  G.isDefaultStatus = true;
  G.childUpload = false;
  for (i = 0; i < len; i++) {
    str += "<tr class='" + (obj[i].new_version == "unknow" ? "unknow" : "") + "'>";
    str += "<td class='fixed' title='" + obj[i].name + "'>" + toHtmlCode(obj[i].name) + "</td>";
    str += "<td class='fixed' title='" + obj[i].current_version + "'>" + obj[i].current_version + "</td>";
    str += "<td>" + showNewVersion(obj[i]) + "</td>";
    str += "<td class='fixed " + (obj[i].status == "0" ? "green" : "") + "'>" + showStatus(obj[i].status) + "</td>";
    str += "</tr>";
    
    // 当状态不是在线 或者 下载失败 或者升级失败时 就是处于升级的过程中
    (obj[i].status != "0" && obj[i].status !="3" && obj[i].status !="6") && (G.noUpgrade = false);

    // 当状态不是在线就是处于升级的过程中
    (obj[i].status != "0") && (G.isDefaultStatus = false);

    // 不是主节点 并且状态在下载中 并且当前不是只有一个节点时 修改子节点正在下载的flag
    obj[i].status == "1" && len != 1 && obj[i].node_type != "controller" && (G.childUpload = true)
   }

  if (len == 1) {
    // 如果只有1个节点则需要升级信息 和 进度条
    G.needUpdate = true;
  }

  // 如果之前有升级状态 之后没有升级状态 则修改值升级flag
  // 不是默认状态， 但是又有一些升级失败或者下载失败的状态 
  if(G.noUpgrade && (!G.lastNoUpgrade || !G.isDefaultStatus)){
    G.startUpgrade = false;
    top.$(".iframe-close").removeClass("none");
    top.$("body").delegate("#gbx_overlay", "click", top.closeIframe);
    $('input[name="upgradeType"]').attr("disabled", false);
  }
  
  // 如果没有子节点下载，并且进度条在等待显示中时 
  if(G.waitReboot && !G.childUpload){
    $("#status_progress").removeClass("none");
    $("#status_checking").addClass("none").html(_(""));
    onlineProgress();
    G.waitReboot= false;
  }

  $("#onlineUpdate").html(str);
  G.lastNoUpgrade = G.noUpgrade;
  updateUpgradeBtn();

  top.initIframeHeight();
}

// 显示新版本信息 无新版本或 位置 或新版本的信息
function showNewVersion(data) {
  if (data.new_version == "unknown") {
    return (
      _("未知") +
      "<a class='ip-remark' href='http://" +
      data.ip_addr +
      "' target='_blank'>" +
      _("点击进入设备配置") +
      "</a>"
    );
  }

  // 没有网络 或者说检查服务器还没有成功时 显示
  if (!G.hasWan || !G.checkServer || data.new_version == "") {
    return _("--");
  }

  if (data.new_version == data.current_version) {
    return _("已经是最新版本");
  }

  G.hasNewVersion = true;

  if (data.node_type == "controller") {
    // 主节点需要升级信息
    G.needUpdate = true;
  }
  // 根据语言获取
  var description = data.version_description && (data.version_description[language] || data.version_description.cn);
  var descriptionArr = [];

  if (description) {
    descriptionArr = description.join("").split("\n");
  }

  var str = "<div class='version' title="+ data.new_version +">" + data.new_version + "</div>";
  str += "<span class='new-version r-icon-new-version'>";
  str += "<div class='description'>";
  str += "<div class='desc-title'>" + _("版本说明") + "</div><ul>";

  for (var i = 0; i < descriptionArr.length; i++) {
    str += "<li>" + descriptionArr[i] + "</li>";
  }

  str += "</ul></div></span>";
  return str;
}
// 返回当前状态
function showStatus(status) {
  var statusObj = {
    0: _("Online"),
    1: _("下载中..."),
    2: _("下载完成等待升级"),
    3: _("下载失败"),
    4: _("升级中..."),
    5: _("升级成功"),
    6: _("升级失败")
  };

  return statusObj[status] || _("检测中...");
}

function setUpdateTimer(isStart) {
  clearInterval(G.updateTimer);
  if (isStart) {
    getUpdateInfo();
    G.updateTimer = setInterval(getUpdateInfo, 5000);
  }
}

window.onload = function () {
  initUpgrade();
  initEvent();
};
window.onunload = function () {
  top.$(".iframe-close").off("click").on("click", top.closeIframe);
};
