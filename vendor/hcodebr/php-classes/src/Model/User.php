<?php
namespace Hcode\Model;
use \Hcode\DB\Sql;
use \Hcode\Model;
class User extends Model{
    const SESSION= "User";
    public static function login($login,$password){
        $sql = new Sql();
        $results= $sql -> select ("SELECT * FROM tb_users WHERE deslogin = :LOGIN",array(":LOGIN"=>$login));
        
        if (count($results)===0){
            throw new \Exception("Usuário inexistente ou invalido.",1);
        }
        
        $data = $results[0];
        if(password_verify($password,$data["despassword"])){
            $user = new User();
            $user->setData($data);
            $_SESSION[User::SESSION] = $user -> getValues();
            
        } else {
            throw new \Exception("Usuário inexistente ou invalido.",1);
        }
        return $user;
    }
    public static function verifyLogin($inadmin=true){

        if (!isset($_SESSION[User::SESSION]) || !$_SESSION[User::SESSION] || !(int)$_SESSION[User::SESSION]["iduser"]>0 || (bool)$_SESSION[User::SESSION]["inadmin"]!==$inadmin){
            header ("Location: /admin/login");
            exit;
        }
    }
    public static function logout(){
        unset ($_SESSION[User::SESSION]);
    }
    public static function listAll(){
        $sql = new Sql();
        return $sql -> select ("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");
    }
    public function save(){
        $sql = new Sql();
       $result =  $sql->select("CALL sp_users_save(:desperson,:deslogin,:despassword,:desemail,:nrphone,:inadmin)",array(
        ":desperson"=>$this->getdesperson(),
        ":deslogin"=>$this->getdeslogin(),
        ":despassword"=>$this->getdespassword(),
        ":desemail"=>$this->getdesemail(),
        ":nrphone"=>$this->getnrphone(),
        ":inadmin"=>$this->getinadmin(),
            
        ));
        
        $this->setData($result[0]);
    }
    
     public function get($id){
        $sql = new Sql();
        $result = $sql -> select ("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser=:ID", array(":ID"=>$id));
        $this->setData($result[0]);
    }
    
    public function update(){
                $sql = new Sql();
       $result =  $sql->select("CALL sp_usersupdate_save(:iduser, :desperson,:deslogin,:despassword,:desemail,:nrphone,:inadmin)",array(
        ":iduser"=>$this->getiduser(),
        ":desperson"=>$this->getdesperson(),
        ":deslogin"=>$this->getdeslogin(),
        ":despassword"=>$this->getdespassword(),
        ":desemail"=>$this->getdesemail(),
        ":nrphone"=>$this->getnrphone(),
        ":inadmin"=>$this->getinadmin(),
            
        ));
        
        $this->setData($result[0]);
    }
    public function delete(){
        $sql = new Sql();
        $sql->query("CALL sp_users_delete(:iduser)",array(":iduser"=>$this->getiduser()));
    }
}
?>

