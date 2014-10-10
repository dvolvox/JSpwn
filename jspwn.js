//JSpwMN!
//TODO - add output html select
// file is included here:
var fs = require('fs');

/*eval(fs.readFileSync(__dirname + '/common/analyzer.js') + '');
eval(fs.readFileSync(__dirname + '/common/engine.js') + '');
*/
var esprima = require('./common/esprima.js');
var engine = require('./common/engine.js');
var analyzer = require('./common/analyzer.js');
//var q = require('q');

var argv = require('optimist').usage('Usage: $node jspwn.js -t [path/to/app] -o [for json output] -c [for custom rules]').demand(['t']).argv;

var results = {};
var dir= argv.t;
var adata=[];
var res = "";
var time_scan = 0;
var cnt = 0;
var output = "";

//Variaveis do Analyzer
var source = ["URL","documentURI","URLUnencoded","baseURI","cookie","referrer","location", "localStorage.getItem","sessionStorage.getItem","sessionStorage.key","responseText", "window.name", "websockets.onMessage","load","ajax","url.parse", "get", "val","data","value"];
var sink = ["eval","setTimeout","setInterval","execScript","document.write","document.writeln","innerHTML","href","src","html","after","append","appendTo","before","insertAfter","insertBefore","prepend","prependTo","replaceWith","parseHTML","jQuery","globalEval","appendChild","create","insert","setContent","setHTML"];
var user_input = ["location"];

function load_vars(){
	console.log("$ SYSTEM: Reading customized rules");
	var file_read_sinks = fs.readFileSync("custom_sink.txt","utf8");
	var file_read_sinksa = file_read_sinks.split('\n');
	for(var a_sinks = 0; a_sinks < file_read_sinksa.length; a_sinks++)
	{
		sink.push(file_read_sinksa[a_sinks]);
	}
	var file_read_sources = fs.readFileSync("custom_source.txt","utf8");
	var file_read_sourcesa = file_read_sources.split('\n');
	for(var a_sources = 0; a_sources < file_read_sourcesa.length; a_sources++)
	{
		source.push(file_read_sourcesa[a_sources]);
	}
	var file_read_users = fs.readFileSync("custom_userinput.txt","utf8");
	var file_read_usersa = file_read_users.split('\n');
	for(var a_user = 0; a_user < file_read_usersa.length; a_user++)
	{
		user_input.push(file_read_usersa[a_user]);
	}
	analyzer.sink = sink;
	analyzer.source = source;
}

//Recursive Function to sumarize all sub folder and files.
function walk(dir) {
    var results = [];
    var list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        var stat = fs.statSync(file);
        if (stat && stat.isDirectory()) results = results.concat(walk(file))
        else
        	if( file.indexOf('vendor') === -1  && file.indexOf('tests') === -1 && file.split('.').pop() == "js") 
        	results.push(file);
    })
    return results;
}

if(argv.c)
{
	load_vars();
}

var files = walk(dir);	
var tmp_data = [];
var input = {};
console.log("$ SYSTEM: Files: " + files.length);

var errors_m = [];


for( var cnt = 0; cnt < files.length; cnt++){
		console.log("$ SYSTEM: Reading File["+ cnt +"]: " + files[cnt]);
		var data = fs.readFileSync(files[cnt], "utf8");
		var start = new Date().getTime();
		var iss = [];
		try {
		    iss = scan(data);
		} catch (e) {
		console.log("$ SYSTEM: ERROR ALERT - " + e.message);
		errors_m.push(files[cnt] + e.message);
		}
		var end = new Date().getTime();
		input = {"id":cnt,"nome":files[cnt],"time":end-start,"issues":iss};
		adata.push(input);
		analyzer.clear_vars();
		engine.clear_vars();
}


//console.log(adata);
var d = new Date();
var path = __dirname + '/output' + d.getDate() + '-' + d.getMonth();

if(argv.o){
	//printout JSON format
	path = path.concat(".json");
	buffer = new Buffer(JSON.stringify(adata));
	fs.open(path, 'w', function(err, fd) {
    if (err) {
        throw 'error opening file: ' + err;
    } else {
        fs.write(fd, buffer, 0, buffer.length, null, function(err) {
            if (err) throw 'error writing file: ' + err;
            fs.close(fd, function() {
                console.log('$ SYSTEM: file written [' + path + ']');
            })
        });
    }
	});
}
else{
	p_html(adata);
}

//Save HTML format
function p_html(jsonobj){
	
	var htmlcontent = '<html><head><title>Output scanner</title></head><body>Data:'+ Date() + '</br><span style="background: none repeat scroll 0% 0% orange;width:300px;height:25px;">&nbsp;&nbsp;&nbsp;&nbsp;Source that reached the Sink&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;<span style="background: none repeat scroll 0% 0% yellow;width:300px;height:25px;">&nbsp;&nbsp;&nbsp;&nbsp;Active Source asigned to variables&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;<span style="background: none repeat scroll 0% 0% LightPink;width:300px;height:25px;">&nbsp;&nbsp;&nbsp;&nbsp;Active Source passed through a function&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;<span style="background: none repeat scroll 0% 0% BurlyWood;width:300px;height:25px;">&nbsp;&nbsp;&nbsp;&nbsp;Source that missed the Sink&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;<span style="background: none repeat scroll 0% 0% grey;width:300px;height:25px;">&nbsp;&nbsp;&nbsp;&nbsp;Non-Active Source asigned to variables&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;<span style="background: none repeat scroll 0% 0% red;width:300px;height:25px;">&nbsp;&nbsp;&nbsp;&nbsp;Active Source reached the Sink&nbsp;&nbsp;&nbsp;&nbsp;</span></br><table>';
	htmlcontent = htmlcontent.concat("</br>ERR:<strong>" + errors_m.length + '</strong></br>');
	for (var cnt_html = 0; cnt_html < jsonobj.length; cnt_html++){
		var tmpj = jsonobj[cnt_html];
		if(tmpj.issues.length != 0){
			htmlcontent = htmlcontent.concat("<tr><td></br></td></tr><tr><td><strong>ID:["+tmpj.id+"]</strong></td><td><strong>FILENAME:["+tmpj.nome+"]</strong></td><td>TIMESCAN:["+tmpj.time+"]</td></tr>");
			for (var cnt_iss = 0; cnt_iss < tmpj.issues.length; cnt_iss++)
			{
				var tmpi = tmpj.issues;
				var tmpi_line = tmpi[cnt_iss].line;
				if(tmpi[cnt_iss].user_input == true){
					tmpi_line = "<mark>" + tmpi[cnt_iss].line + "</mark>";
				}
				htmlcontent = htmlcontent.concat("<tr><td style='color:"+tmpi[cnt_iss].css+"' >"+tmpi[cnt_iss].nome+"</td><td>"+tmpi_line+"</td><td>"+tmpi[cnt_iss].code+"</td></th>");		
			}
		}
	}
	htmlcontent = htmlcontent.concat("</table>");



	path = path.concat(".html");
	buffer = new Buffer(htmlcontent);
	fs.open(path, 'w', function(err, fd) {
    if (err) {
        throw 'error opening file: ' + err;
    } else {
        fs.write(fd, buffer, 0, buffer.length, null, function(err) {
            if (err) throw 'error writing file: ' + err;
            fs.close(fd, function() {
                console.log('$ SYSTEM: file written [' + path + ']');
            })
        });
    }
	});

}

//Execute JSPrime function
function scan(data){
	//console.log(time);
	//var ret = analyze(data); 
	var result = esprima.parse(data, options);
	var str_result = JSON.stringify(result, null, 4);
	engine.analyze(str_result);
	engine.asignFunctionReturnValue(analyzer.sink);
	var ret = analyzer.analyzeArrays(engine.real_func_names, engine.real_func_call, engine.real_variable_const, engine.real_variable_var, engine.real_variable_obj, engine.startScope, engine.endScope, data, res);
	var tmp_array = [];
	var file_a = data.split('\n');
	var is_ui = false;

	for(var i = 0; i < ret.length; i++){
		var color = ret[i][0];
		var tmp_i = "";
		var css = "";
		if ( color == 'orange'){
			tmp_i = "Active Source";
			css ="#ffc04c";
	    }
	    if ( color == 'yellow'){
			tmp_i = "Active Variable";
			css = "#ffff4c";
	    }
	    if ( color == 'grey'){
	    	tmp_i = "Non Active Variable";	
	    	css = "grey";
	    }
	    if ( color == 'BurlyWood'){
	    	tmp_i = "Non Active Source";
	    	css = "BurlyWood";
	    }
	    if ( color == 'LightPink'){
	    	tmp_i = "Active function";
	    	css = "#ff7fff";
	    }
	    if ( color == 'red'){
			tmp_i = "Active Sink";
			css = "#ff6666";
	    }
	    //console.log(file_a);
	    //console.log("LINHDA DO FICHEIRO VULN?!: " + file_a[ret[i][1]-1] );
	    if(file_a[ret[i][1]-1] != undefined && file_a[ret[i][1]-1] != ' ' && file_a[ret[i][1]-1] != '' && file_a[ret[i][1]-1].charAt(1) != '*'){
		    is_ui = check_is_ui(file_a[ret[i][1]-1]);
		    //console.log(tmp_i + ret[i][1] + file_a[ret[i][0]-1] + css + is_ui);
			tmp_array.push(new_issue(tmp_i,ret[i][1],file_a[ret[i][1]-1],css,is_ui));
		}
	}
	//console.log(tmp_array);
	return tmp_array;
}

function check_is_ui(str){
	for (var reg_cnt = 0; reg_cnt < user_input.length; reg_cnt++ )
		if(str.indexOf(user_input[reg_cnt]) != -1){
			return true
		}
		return false;
}

//create a new data struture
function new_issue(name,line,code,css,ui){
	return {"nome": name, "line":line, "code": code, "css":css, "user_input": ui};
}