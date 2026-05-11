<?php
// Real nextcloud `lib/private/DB/MySqlTools.php` shape.  `$variables` is
// built from a literal-keyed array plus optional literal subscript-set
// extensions; the foreach-key `$var` ranges over a finite metachar-free
// set (`innodb_file_per_table`, `innodb_file_format`,
// `innodb_large_prefix`).  The interpolated SQL `SHOW VARIABLES LIKE
// '$var'` is bounded to the literal key set.

namespace OC\DB;

class MySqlTools
{
    public function supports4ByteCharset($connection): bool
    {
        $variables = ['innodb_file_per_table' => 'ON'];
        if (!$this->isMariaDBWithLargePrefix($connection)) {
            $variables['innodb_file_format'] = 'Barracuda';
            $variables['innodb_large_prefix'] = 'ON';
        }

        foreach ($variables as $var => $val) {
            $result = $connection->executeQuery("SHOW VARIABLES LIKE '$var'");
            $row = $result->fetch();
            $result->closeCursor();
            if ($row === false) {
                return false;
            }
            if (strcasecmp($row['Value'], $val) !== 0) {
                return false;
            }
        }
        return true;
    }

    protected function isMariaDBWithLargePrefix($connection): bool
    {
        return false;
    }
}
