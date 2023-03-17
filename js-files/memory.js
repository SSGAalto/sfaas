function input(params) {
    var it = params.iterations || 1;
    var succ = true;
    var a1 = [];
    var a2 = [];
    function sum(x, y, n) {
        var i;
        for (i = 0; i < n; i++){
            x[i] += y[i];
        }
    }
    function fill(x, n, value) {
        var i;
        for (i = 0; i < n; i++)
        x[i] = value;
    }
    function check(x, n, value) {
        var i;
        for (i = 0; i < n; i++) {
            if (x[i] != value){
                return false;
            }
        }
        return true;
    }
    fill(a1, it, 17.25);
    fill(a2, it, 1.25);
    sum(a1, a2, it);
    if (!check(a1, it, 18.5)) {
        succ = false;
    }
    return JSON.stringify({success:succ, iterations:it});
}
