<?php
/**************************************************************************
* This file is part of the WebIssues Server program
* Copyright (C) 2006 Michał Męciński
* Copyright (C) 2007-2017 WebIssues Team
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
**************************************************************************/

require_once( '../../../system/bootstrap.inc.php' );

class Server_Api_Issue_Load
{
    public function run( $arguments )
    {
        $issueId = isset( $arguments[ 'issueId' ] ) ? (int)$arguments[ 'issueId' ] : null;
        $description = isset( $arguments[ 'description' ] ) ? (bool)$arguments[ 'description' ] : false;
        $attributes = isset( $arguments[ 'attributes' ] ) ? (bool)$arguments[ 'attributes' ] : false;
        $history = isset( $arguments[ 'history' ] ) ? (bool)$arguments[ 'history' ] : false;
        $modifiedSince = isset( $arguments[ 'modifiedSince' ] ) ? (int)$arguments[ 'modifiedSince' ] : 0;
        $filter = isset( $arguments[ 'filter' ] ) ? (int)$arguments[ 'filter' ] : System_Api_HistoryProvider::AllHistory;
        $html = isset( $arguments[ 'html' ] ) ? (bool)$arguments[ 'html' ] : false;
        $unread = isset( $arguments[ 'unread' ] ) ? (bool)$arguments[ 'unread' ] : false;

        if ( $issueId == null )
            throw new Server_Error( Server_Error::InvalidArguments );
        if ( $filter < System_Api_HistoryProvider::AllHistory || $filter > System_Api_HistoryProvider::CommentsAndFiles )
            throw new Server_Error( Server_Error::InvalidArguments );

        $issueManager = new System_Api_IssueManager();
        $issue = $issueManager->getIssue( $issueId );

        $formatter = new System_Api_Formatter();
        $principal = System_Api_Principal::getCurrent();

        $resultDetails[ 'id' ] = $issue[ 'issue_id' ];
        $resultDetails[ 'name' ] = $issue[ 'issue_name' ];
        $resultDetails[ 'project' ] = $issue[ 'project_name' ];
        $resultDetails[ 'folder' ] = $issue[ 'folder_name' ];
        $resultDetails[ 'type' ] = $issue[ 'type_name' ];
        $resultDetails[ 'access' ] = $issue[ 'project_access' ];
        $resultDetails[ 'createdDate' ] = $formatter->formatDateTime( $issue[ 'created_date' ], System_Api_Formatter::ToLocalTimeZone );
        $resultDetails[ 'createdBy' ] = $issue[ 'created_by' ];
        $resultDetails[ 'modifiedDate' ] = $formatter->formatDateTime( $issue[ 'modified_date' ], System_Api_Formatter::ToLocalTimeZone );
        $resultDetails[ 'modifiedBy' ] = $issue[ 'modified_by' ];
        $resultDetails[ 'own' ] = $issue[ 'created_user' ] == $principal->getUserId();
        $resultDetails[ 'stamp' ] = $issue[ 'stamp_id' ];

        $result[ 'details' ] = $resultDetails;

        if ( $html )
            System_Web_Base::setLinkMode( System_Web_Base::RouteLinks );

        if ( $description ) {
            if ( $issue[ 'descr_id' ] != null ) {
                $descr = $issueManager->getDescription( $issue );

                if ( ( $descr[ 'modified_date' ] - $issue[ 'created_date' ] ) > 180 || $descr[ 'modified_user' ] != $issue[ 'created_user' ] ) {
                    $resultDescription[ 'modifiedBy' ] = $descr[ 'modified_by' ];
                    $resultDescription[ 'modifiedDate' ] = $formatter->formatDateTime( $descr[ 'modified_date' ], System_Api_Formatter::ToLocalTimeZone );
                }

                $resultDescription[ 'text' ] = $this->convertText( $descr[ 'descr_text' ], $html, $descr[ 'descr_format' ] );

                $result[ 'description' ] = $resultDescription;
            } else {
                $result[ 'description' ] = null;
            }
        }

        if ( $attributes ) {
            $serverManager = new System_Api_ServerManager();
            $hideEmpty = $serverManager->getSetting( 'hide_empty_values' );

            $attributeValues = $issueManager->getAllAttributeValuesForIssue( $issue, $hideEmpty == '1' ? System_Api_IssueManager::HideEmptyValues : 0 );

            foreach ( $attributeValues as &$value ) {
                $formatted = $formatter->convertAttributeValue( $value[ 'attr_def' ], $value[ 'attr_value' ], System_Api_Formatter::MultiLine );
                $value[ 'attr_value' ] = $this->convertText( $formatted, $html );
            }

            $typeManager = new System_Api_TypeManager();
            $type = $typeManager->getIssueTypeForIssue( $issue );

            $viewManager = new System_Api_ViewManager();
            $attributeValues = $viewManager->sortByAttributeOrder( $type, $attributeValues );

            $result[ 'attributes' ] = array();

            foreach( $attributeValues as $value ) {
                $resultAttr = array();
                $resultAttr[ 'name' ] = $value[ 'attr_name' ];
                $resultAttr[ 'value' ] = $value[ 'attr_value' ];
                $result[ 'attributes' ][] = $resultAttr;
            }
        }

        if ( $history ) {
            if ( $principal->isAuthenticated() ) {
                $stateManager = new System_Api_StateManager();
                $stateManager->setIssueRead( $issue, $unread ? 0 : $issue[ 'stamp_id' ] );
            }

            $historyProvider = new System_Api_HistoryProvider();
            $historyProvider->setIssueId( $issueId );

            if ( $modifiedSince > 0 )
                $historyProvider->setModifiedSince( $modifiedSince );

            $connection = System_Core_Application::getInstance()->getConnection();

            $query = $historyProvider->generateSelectQuery( $filter );
            $page = $connection->queryPageArgs( $query, $historyProvider->getOrderBy( System_Api_HistoryProvider::Ascending ), System_Const::INT_MAX, 0, $historyProvider->getQueryArguments() );

            $history = $historyProvider->processPage( $page );

            $localeHelper = new System_Web_LocaleHelper();

            $result[ 'history' ] = array();

            foreach ( $history as $id => $item ) {
                $resultItem = array();

                $resultItem[ 'id' ] = $item[ 'change_id' ];
                $resultItem[ 'type' ] = $item[ 'change_type' ];
                $resultItem[ 'createdDate' ] = $formatter->formatDateTime( $item[ 'created_date' ], System_Api_Formatter::ToLocalTimeZone );
                $resultItem[ 'createdBy' ] = $item[ 'created_by' ];
                if ( ( $item[ 'modified_date' ] - $item[ 'created_date' ] ) > 180 || $item[ 'modified_user' ] != $item[ 'created_user' ] ) {
                    $resultItem[ 'modifiedDate' ] = $formatter->formatDateTime( $item[ 'modified_date' ], System_Api_Formatter::ToLocalTimeZone );
                    $resultItem[ 'modifiedBy' ] = $item[ 'modified_by' ];
                }

                if ( isset( $item[ 'comment_text' ] ) )
                    $resultItem[ 'text' ] = $this->convertText( $item[ 'comment_text' ], $html, $item[ 'comment_format' ] );

                if ( isset( $item[ 'file_name' ] ) )
                    $resultItem[ 'name' ] = $item[ 'file_name' ];
                if ( isset( $item[ 'file_descr' ] ) )
                    $resultItem[ 'description' ] = $this->convertText( $item[ 'file_descr' ], $html );
                if ( isset( $item[ 'file_size' ] ) )
                    $resultItem[ 'size' ] = $localeHelper->formatFileSize( $item[ 'file_size' ] );

                if ( isset( $item[ 'from_project_name' ] ) )
                    $resultItem[ 'fromProject' ] = $item[ 'from_project_name' ];
                if ( isset( $item[ 'from_folder_name' ] ) )
                    $resultItem[ 'fromFolder' ] = $item[ 'from_folder_name' ];
                if ( isset( $item[ 'to_project_name' ] ) )
                    $resultItem[ 'toProject' ] = $item[ 'to_project_name' ];
                if ( isset( $item[ 'to_folder_name' ] ) )
                    $resultItem[ 'toFolder' ] = $item[ 'to_folder_name' ];

                if ( isset( $item[ 'changes' ] ) ) {
                    $resultItem[ 'changes' ] = array();

                    foreach ( $item[ 'changes' ] as $change ) {
                        $resultChange = array();

                        $resultChange[ 'type' ] = $change[ 'change_type' ];
                        if ( isset( $change[ 'attr_name' ] ) )
                            $resultChange[ 'name' ] = $change[ 'attr_name' ];

                        $newValue = $change[ 'value_new' ];
                        $oldValue = $change[ 'value_old' ];
                        if ( $change[ 'attr_def' ] != null ) {
                            $newValue = $formatter->convertAttributeValue( $change[ 'attr_def' ], $newValue );
                            $oldValue = $formatter->convertAttributeValue( $change[ 'attr_def' ], $oldValue );
                        }

                        $resultChange[ 'new' ] = $this->convertText( $newValue, $html );
                        $resultChange[ 'old' ] = $this->convertText( $oldValue, $html );

                        $resultItem[ 'changes' ][] = $resultChange;
                    }
                }

                $resultItem[ 'own' ] = $item[ 'created_user' ] == $principal->getUserId();

                $result[ 'history' ][] = $resultItem;
            }
        }

        return $result;
    }

    private function convertText( $text, $html, $format = System_Const::PlainText )
    {
        if ( $html ) {
            if ( $format == System_Const::TextWithMarkup )
                return System_Web_MarkupProcessor::convertToHtml( $text, $prettyPrint );
            else
                return System_Web_LinkLocator::convertToHtml( $text );
        } else {
            return $text;
        }
    }
}

System_Bootstrap::run( 'Server_Api_Application', 'Server_Api_Issue_Load' );
