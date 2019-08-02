<?php if ( !defined( 'WI_VERSION' ) ) die( -1 ); ?>

<h1>
<?php
    if ( !empty( $folderName ) ):
        echo $this->mailLink( '/client/index.php#' . $viewUrl, $typeName . ' &mdash; ' . $viewName . ' ' . $this->t( 'text.in' ) . ' ' . $projectName . ' &mdash; ' . $folderName );
    elseif ( !empty( $projectName ) ):
        echo $this->mailLink( '/client/index.php#' . $viewUrl, $typeName . ' &mdash; ' . $viewName . ' ' . $this->t( 'text.in' ) . ' ' . $projectName );
    else:
        echo $this->mailLink( '/client/index.php#' . $viewUrl, $typeName . ' &mdash; ' . $viewName );
    endif
?>
</h1>

<table class="grid">
<tr>
<?php foreach ( $columns as $column => $name ): ?>
<th><?php echo $headers[ $column ] ?></th>
<?php endforeach ?>
</tr>
<?php foreach ( $issues as $issueId => $issue ): ?>
<tr>
<?php foreach ( $columns as $column => $name ): ?>
<td>
<?php
    if ( $column == System_Api_Column::Name ):
        echo $this->mailLink( '/client/index.php#/issues/' . $issueId, $issue[ $name ] );
    elseif ( $column == System_Api_Column::Location ):
        echo $issue[ 'project_name' ] . ' &mdash; ' . $issue[ 'folder_name' ];
    else:
        echo $issue[ $name ];
    endif;
?>
</td>
<?php endforeach ?>
</tr>
<?php endforeach ?>
</table>

<?php foreach ( $details as $issueId => $issue ): ?>

<h2>
<?php echo $this->mailLink( '/client/index.php#/issues/' . $issueId, $issue[ 'issue_name' ] ); ?>
</h2>

<div class="sub-pane-wrapper">

<table class="sub-pane-layout">
<tr>
<td class="top-sub-pane"<?php if ( empty( $issue[ 'attribute_values' ] ) ) echo ' colspan="2"' ?>>

<h3><?php echo $this->t( 'title.Properties' ) ?></h3>

<table class="info-list">
<tr>
<td><?php echo $this->t( 'label.ID' ) ?></td>
<td><?php echo $issue[ 'issue_id' ] ?></td>
</tr>
<tr>
<td><?php echo $this->t( 'label.Type' ) ?></td>
<td><?php echo $issue[ 'type_name' ] ?></td>
</tr>
<tr>
<td><?php echo $this->t( 'label.Location' ) ?></td>
<td><?php echo $issue[ 'project_name' ] . ' &mdash; ' . $issue[ 'folder_name' ] ?></td>
</tr>
<tr>
<td><?php echo $this->t( 'label.Created' ) ?></td>
<td><?php echo $issue[ 'created_date' ] . ' &mdash; ' . $issue[ 'created_by' ] ?></td>
</tr>
<tr>
<td><?php echo $this->t( 'label.LastModified' ) ?></td>
<td><?php echo $issue[ 'modified_date' ] . ' &mdash; ' . $issue[ 'modified_by' ] ?></td>
</tr>
</table>

</td>
<?php if ( !empty( $issue[ 'attribute_values' ] ) ): ?>
<td class="top-sub-pane">

<h3><?php echo $this->t( 'title.Attributes' ) ?></h3>

<table class="info-list">
<?php foreach( $issue[ 'attribute_values' ] as $value ): ?>
<tr>
<td><?php echo $value[ 'attr_name' ] ?>:</td>
<td><?php echo $value[ 'attr_value' ] ?></td>
</tr>
<?php endforeach ?>
</table>

</td>
<?php endif ?>
</tr>

<?php if ( !empty( $issue[ 'description' ] ) ): ?>
<tr>
<td colspan="2" class="bottom-sub-pane">

<h3>
<?php
    echo $this->t( 'title.Description' );
    if ( $issue[ 'description' ][ 'is_modified' ] ):
        echo '&nbsp; <span class="edited">(' . $this->t( 'label.LastEdited' ) . ' ' . $issue[ 'description' ][ 'modified_date' ] . ' &mdash; ' . $issue[ 'description' ][ 'modified_by' ] . ')</span>';
    endif;
?>
</h3>

<div class="comment-text"><?php echo $issue[ 'description' ][ 'descr_text' ] ?></div>

</td>
</tr>
<?php endif ?>

<?php if ( !empty( $issue[ 'history' ] ) ): ?>

<tr>
<td colspan="2" class="bottom-sub-pane">

<h3><?php echo $this->t( 'title.IssueHistory' ) ?></h3>

<?php
    foreach ( $issue[ 'history' ] as $id => $item ):
?>

<div class="history-item">

<h4>
<?php
    echo  $item[ 'created_date' ] . ' &mdash; ' . $item[ 'created_by' ];
    if ( $item[ 'is_modified' ] ):
        echo '&nbsp; <span class="edited">(' . $this->t( 'label.LastEdited' ) . ' ' . $item[ 'modified_date' ] . ' &mdash; ' . $item[ 'modified_by' ] . ')</span>';
    endif;
?>
</h4>

<?php
    switch ( $item[ 'change_type' ] ):
    case System_Const::IssueCreated:
    case System_Const::IssueRenamed:
    case System_Const::ValueChanged:
?>

<ul class="changes">
<?php foreach ( $item[ 'changes' ] as $change ): ?>
<li>
<?php
    switch ( $change[ 'change_type' ] ):
    case System_Const::IssueCreated:
        echo $this->t( 'label.Name' ) . ' "' . $change[ 'value_new' ] . '"';
        break;
    case System_Const::IssueRenamed:
        echo $this->t( 'label.Name' ) . ' "' . $change[ 'value_old' ] . '" &raquo; "' . $change[ 'value_new' ] . '"';
        break;
    case System_Const::ValueChanged:
        $from = ( $change[ 'value_old' ] == '' ) ? $this->t( 'text.empty' ) : '"' . $change[ 'value_old' ] . '"';
        $to = ( $change[ 'value_new' ] == '' ) ? $this->t( 'text.empty' ) : '"' . $change[ 'value_new' ] . '"';
        echo $change[ 'attr_name' ] . ': ' . $from . ' &raquo; ' . $to;
        break;
    endswitch;
?>
</li>
<?php endforeach ?>
</ul>

<?php
    break;
    case System_Const::CommentAdded:
?>

<div class="comment-text"><?php echo $item[ 'comment_text' ] ?></div>

<?php
    break;
    case System_Const::FileAdded:
?>

<div class="attachment">
<?php
    echo $this->mailLink( $this->appendQueryString( '/client/file.php', array( 'id' => $id ) ), $item[ 'file_name' ] ) . ' (' . $item[ 'file_size' ] . ')';
    if ( $item[ 'file_descr' ] != '' ):
        echo ' &mdash; ' . $item[ 'file_descr' ];
    endif;
?>
</div>

<?php
    break;
    case System_Const::IssueMoved:
?>

<ul class="changes">
<li>
<?php
    $from = ( $item[ 'from_folder_name' ] == '' ) ? $this->t( 'text.unknown' ) : '"' . $item[ 'from_folder_name' ] . '"';
    $to = ( $item[ 'to_folder_name' ] == '' ) ? $this->t( 'text.unknown' ) : '"' . $item[ 'to_folder_name' ] . '"';
    echo $this->t( 'label.Location' ) . ' ' . $from . ' &rarr; ' . $to;
?>
</li>
</ul>

<?php
    break;
    endswitch;
?>

</div>

<?php
    endforeach;
?>

</td>
</tr>

<?php endif ?>

</table>

</div>

<?php endforeach ?>

<p><?php echo $this->t( 'prompt.AlertEmail' ) ?></p>
