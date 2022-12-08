# adapted from: https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage

# Remark: This script contains functionality for GF(2^n), but currently works only over GF(p)! A few small adaptations are needed for GF(2^n).
from sage.rings.polynomial.polynomial_gf2x import GF2X_BuildIrred_list

if len(sys.argv) < 4:
    print("Usage: <script> <field> <s_box> <num_cells> <prime_number_hex>")
    print("field = 1 for GF(p)")
    print("s_box = 0 for x^alpha, s_box = 1 for x^(-1)")
    exit()

# Parameters
FIELD = int(sys.argv[1]) # 0 .. GF(2^n), 1 .. GF(p)
SBOX = int(sys.argv[2]) # 0 .. x^alpha, 1 .. x^(-1)
NUM_CELLS = int(sys.argv[3]) # t

INIT_SEQUENCE = []

PRIME_NUMBER = 0
if FIELD == 1 and len(sys.argv) != 5:
    print("Please specify a prime number (in hex format)!")
    exit()
elif FIELD == 1 and len(sys.argv) == 5:
    PRIME_NUMBER = int(sys.argv[4], 16) # e.g. 0xa7, 0xFFFFFFFFFFFFFEFF, 0xa1a42c3efd6dbfe08daa6041b36322ef

F = GF(PRIME_NUMBER)

def create_mds_p(t):
    M = matrix(F, t, t)
    while True:
        flag = True
        rand_list = [F(i) for i in range(0, 2*t)]
        xs = rand_list[:t]
        ys = rand_list[t:]
        for i in range(0, t):
            for j in range(0, t):
                if (flag == False) or ((xs[i] + ys[j]) == 0):
                    flag = False
                else:
                    entry = (xs[i] + ys[j])^(-1)
                    M[i, j] = entry
        if flag == False:
            continue
        return M

def generate_vectorspace(round_num, M_round, NUM_CELLS):
    t = NUM_CELLS
    s = 1
    V = VectorSpace(F, t)
    if round_num == 0:
        return V
    elif round_num == 1:
        return V.subspace(V.basis()[s:])
    else:
        mat_temp = matrix(F)
        for i in range(0, round_num-1):
            add_rows = []
            for j in range(0, s):
                add_rows.append(M_round[i].rows()[j][s:])
            mat_temp = matrix(mat_temp.rows() + add_rows)
        r_k = mat_temp.right_kernel()
        extended_basis_vectors = []
        for vec in r_k.basis():
            extended_basis_vectors.append(vector([0]*s + list(vec)))
        S = V.subspace(extended_basis_vectors)
        return S

def subspace_times_matrix(subspace, M, NUM_CELLS):
    t = NUM_CELLS
    V = VectorSpace(F, t)
    subspace_basis = subspace.basis()
    new_basis = []
    for vec in subspace_basis:
        new_basis.append(M * vec)
    new_subspace = V.subspace(new_basis)
    return new_subspace

# Returns True if the matrix is considered secure, False otherwise
def algorithm_1(M, NUM_CELLS):
    t = NUM_CELLS
    s = 1
    r = floor((t - s) / float(s))

    # Generate round matrices
    M_round = []
    for j in range(0, t+1):
        M_round.append(M^(j+1))

    for i in range(1, r+1):
        mat_test = M^i
        entry = mat_test[0, 0]
        mat_target = matrix.circulant(vector([entry] + ([F(0)] * (t-1))))

        if (mat_test - mat_target) == matrix.circulant(vector([F(0)] * (t))):
            return [False, 1]

        S = generate_vectorspace(i, M_round, t)
        V = VectorSpace(F, t)

        basis_vectors= []
        for eigenspace in mat_test.eigenspaces_right(format='galois'):
            if (eigenspace[0] not in F):
                continue
            vector_subspace = eigenspace[1]
            intersection = S.intersection(vector_subspace)
            basis_vectors += intersection.basis()
        IS = V.subspace(basis_vectors)
        if IS.dimension() >= 1 and IS != V:
            return [False, 2]
        for j in range(1, i+1):
            S_mat_mul = subspace_times_matrix(S, M^j, t)
            if S == S_mat_mul:
                print("S.basis():\n", S.basis())
                return [False, 3]
    return [True, 0]

# Returns True if the matrix is considered secure, False otherwise
def algorithm_2(M, NUM_CELLS):
    t = NUM_CELLS
    s = 1
    V = VectorSpace(F, t)
    trail = [None, None]
    test_next = False
    I = range(0, s)
    I_powerset = list(sage.misc.misc.powerset(I))[1:]
    for I_s in I_powerset:
        test_next = False
        new_basis = []
        for l in I_s:
            new_basis.append(V.basis()[l])
        IS = V.subspace(new_basis)
        for i in range(s, t):
            new_basis.append(V.basis()[i])
        full_iota_space = V.subspace(new_basis)
        for l in I_s:
            v = V.basis()[l]
            while True:
                delta = IS.dimension()
                v = M * v
                IS = V.subspace(IS.basis() + [v])
                if IS.dimension() == t or IS.intersection(full_iota_space) != IS:
                    test_next = True
                    break
                if IS.dimension() <= delta:
                    break
            if test_next == True:
                break
        if test_next == True:
            continue
        return [False, [IS, I_s]]
    return [True, None]

# Returns True if the matrix is considered secure, False otherwise
def algorithm_3(M, NUM_CELLS):
    t = NUM_CELLS
    l = 4*t
    for r in range(2, l+1):
        res_alg_2 = algorithm_2(M^r, t)
        if res_alg_2[0] == False:
            return [False, None]
    return [True, None]

def generate_matrix(FIELD, NUM_CELLS):
    if FIELD == 0:
        print("Matrix generation not implemented for GF(2^n).")
        exit(1)
    elif FIELD == 1:
        mds_matrix = create_mds_p(NUM_CELLS)
        result_1 = algorithm_1(mds_matrix, NUM_CELLS)
        result_2 = algorithm_2(mds_matrix, NUM_CELLS)
        result_3 = algorithm_3(mds_matrix, NUM_CELLS)
        while result_1[0] == False or result_2[0] == False or result_3[0] == False:
            mds_matrix = create_mds_p(NUM_CELLS)
            result_1 = algorithm_1(mds_matrix, NUM_CELLS)
            result_2 = algorithm_2(mds_matrix, NUM_CELLS)
            result_3 = algorithm_3(mds_matrix, NUM_CELLS)
        return mds_matrix

def output_linear_layer_arkff(M,  t):
    matrix_string = "vec!["
    for i in range(0, t):
        matrix_string += "vec![" + ",".join(["Fp(field_new!(Fr, \"{}\"))".format(int(entry)) for entry in M[i]]) + "]"
        if i < (t-1):
            matrix_string += ","
    matrix_string += "]"
    file = open('width'+str(t),'w')
    file.write(matrix_string)

linear_layer = generate_matrix(FIELD, NUM_CELLS)
output_linear_layer_arkff(linear_layer,  NUM_CELLS)
