//SCANJS + JSPRIME TESTE CLI
// file is included here:
var fs = require('fs');

eval(fs.readFileSync(__dirname + '/common/analyzer.js') + '');
eval(fs.readFileSync(__dirname + '/common/engine.js') + '');

var argv = require('optimist').usage('Usage: $node jspwn.js -t [path/to/app]').demand(['t']).argv;

var results = {};
var dir= argv.t;
var adata=[];
var res = "";
var htmlcontent = "<html><head><title>Output scanner</title></head><body>Data:"+ Date() + "</br><table>";
var time_scan = 0;
var cnt = 0;

//Recursive Function to sumarize all sub folder and files.
function walk(dir) {
    var results = [];
    var list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        var stat = fs.statSync(file);
        if (stat && stat.isDirectory()) results = results.concat(walk(file))
        else results.push(file);
    })
    return results;
}

var files = walk(dir);
console.log("$ SYSTEM: Files: " + files);
for( var i = 0; i < files.length; i++){
	var data = fs.readFileSync(files[i], "utf8");
	adata.push({"id":i,"nome":files[i],"code":data});
}

console.log(adata);

for(var ct = 0 ; ct < adata.length; ct++){
	htmlcontent = htmlcontent.concat(scan(adata[ct]));
	//console.log(adata);  //socket.emit('init', {data: data});
}

htmlcontent = htmlcontent.concat("</table><br><strong>Time Scan(ms):</strong>"+time_scan+"</body></html>");
var d = new Date();
var path = __dirname + '/output' + d.getDate() + '-' + d.getMonth() + '.html';
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

//console.log(htmlcontent);


//Execute JSPrime function
function scan(data){
	//console.log(time);
	code = data.code;
	var ret = "</br><table><tr><td><strong>"+data.nome+"</strong></td><td><strong>["+data.id+"]<strong></td></br>"
	var start = new Date().getTime();
	var ret_2 = analyze(code); 
	var end = new Date().getTime();
	var obj_json = {};
	time_scan+=end-start;
	obj_json = {"ScanTime":end-start, "nfic":data.nome,"issues":[]};

	var file_a = code.split('\n');
	//console.log(code);

	//console.log();
	//console.log('RESULTADO DA TRAFULHICE: ' + ret_2);
	var tmp_array = [];
	for(var i = 0; i < ret_2.length; i++){
		var color = ret_2[i][1];
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
	    if ( color == '#FF00FF'){
	    	tmp_i = "Active function";
	    	css = "#ff7fff";
	    }
	    if ( color == 'red'){
			tmp_i = "Active Sink";
			css = "#ff6666";
	    }   
		tmp_array.push(new_issue(tmp_i,ret_2[i][0],file_a[ret_2[i][0]-1],css));
/*		console.log('Resultado numero:'+ i);
		console.log('linha:' + ret_2[i][0]);
		console.log('Tipo:' + ret_2[i][1]);
		console.log('Codigo:' + file_a[ret_2[i][0]-1]);*/
	}
	obj_json.issues = tmp_array;
	//console.log("OBJJSON" + obj_json.issues);

	//htmlcontent = htmlcontent.concat(JSON.stringify(obj_json));
	for(var x = 0; x < obj_json.issues.length; x++){
		console.log(obj_json.issues[x]);
		ret = ret.concat("<tr><td><span style=\"color:"+ obj_json.issues[x].css + "\">"+ obj_json.issues[x].nome + "</span></td><td>"+ obj_json.issues[x].line +"</td><td>"+ obj_json.issues[x].code +"</td></tr>");
	}
	return ret;
}

//create a new data struture
function new_issue(name,line,code,css){
	return {"nome": name, "line":line, "code": code, "css":css};
}

/*
fs.readdir(dir,function(err,files){
    if (err) throw err;
    var c=0;
    files.forEach(function(file){
        c++;
        fs.readFile(dir+'/'+file,'utf-8',function(err,html){
            if (err) throw err;
            data.push({"id":c,"fic":file, "code":html});
            if (0===--c) {
                for(var i = 0 ; i < data.length; i++){
                	htmlcontent = htmlcontent.concat(scan(data[i]));
                	console.log(data);  //socket.emit('init', {data: data});

                }
                htmlcontent = htmlcontent.concat("</table></body></html>");
				write2file(htmlcontent);
				console.log(htmlcontent);
            }
        });
    });
});*/